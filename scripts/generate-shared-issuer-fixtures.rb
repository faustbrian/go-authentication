#!/usr/bin/env ruby
# Synthetic public verification fixtures; no private key is retained.
require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "tmpdir"

openssl = ENV.fetch("OPENSSL_BIN", "openssl")
version, error, status = Open3.capture3(openssl, "version")
abort("OpenSSL 3.6.4 is required") unless status.success? && error.empty? && version.start_with?("OpenSSL 3.6.4 ")
root = File.expand_path("..", __dir__)
output = File.join(root, "testdata", "shared-issuer")
FileUtils.mkdir_p(output)

work = Dir.mktmpdir("authentication-fixtures-")
begin
  private_key = File.join(work, "private.pem")
  run = lambda do |*args|
    _out, _err, result = Open3.capture3(openssl, *args)
    abort("independent signing command failed") unless result.success?
  end
  run.call("genpkey", "-algorithm", "ED25519", "-out", private_key)
  public_file = File.join(work, "public.der")
  run.call("pkey", "-in", private_key, "-pubout", "-outform", "DER", "-out", public_file)
  public_der = File.binread(public_file)
  abort("invalid independent public-key encoding") unless public_der.bytesize == 44 && public_der.unpack1("H*").start_with?("302a300506032b6570032100")
  public_key = Base64.strict_encode64(public_der[-32, 32])
  sign = lambda do |bytes|
    input = File.join(work, "input")
    signature = File.join(work, "signature")
    File.binwrite(input, bytes)
    run.call("pkeyutl", "-sign", "-rawin", "-inkey", private_key, "-in", input, "-out", signature)
    File.binread(signature)
  end
  encode = ->(bytes) { Base64.urlsafe_encode64(bytes, padding: false) }
  header = encode.call(JSON.generate({alg: "EdDSA", typ: "at+jwt", kid: "key"}))
  claims = {
    iss: "https://issuer.example", aud: "resource", sub: "organization", client_id: "workload",
    iat: 1790856000, exp: 1790856060, jti: "abcdefghijklmnopqrstuv", purpose: "access-token",
    environment: "test", method: "password", assurance: 2,
    owner: {kind: "organization", id: "organization", version: 3},
    actor: {kind: "user", id: "human", version: 4}, tenant: "tenant",
    tenant_version: 5, client_version: 6, signing_version: 7,
    membership_id: "membership", membership_version: 8,
    root_credential: {id: "credential", version: 1, expires_at: "0001-01-01T00:00:00Z"},
    root_grant: {id: "root", version: 2, expires_at: "2026-10-01T12:05:00Z"},
    parents: [{id: "parent", version: 9, expires_at: "2026-10-01T12:03:00Z"}], scopes: ["read"]
  }
  token = lambda do |body|
    prefix = "#{header}.#{encode.call(JSON.generate(body))}"
    "#{prefix}.#{encode.call(sign.call(prefix))}"
  end
  variants = {valid: claims}
  {
    wrong_environment: ->(c) { c[:environment] = "other" },
    id_token: ->(c) { c[:purpose] = "id-token" },
    missing_root: ->(c) { c[:root_grant][:id] = "" },
    cycle: ->(c) { c[:parents][0][:id] = c[:jti] },
    excessive_depth: ->(c) { c[:parents] = 5.times.map { |n| {id: "parent-#{n}", version: 1, expires_at: "2026-10-01T12:03:00Z"} } }
  }.each do |name, mutate|
    copy = JSON.parse(JSON.generate(claims), symbolize_names: true)
    mutate.call(copy)
    variants[name] = copy
  end
  dimensions = [
    ["root-credential", "credential", 1], ["root-grant", "root", 2],
    ["owner", "organization", 3], ["tenant", "tenant", 5],
    ["client", "workload", 6], ["signing", "key", 7],
    ["parent-grant", "parent", 9], ["actor", "human", 4], ["membership", "membership", 8]
  ].map do |kind, id, revision|
    {Dimension: {Kind: kind, ID: id, Version: revision}, Active: true,
      VerifiedAt: "2026-10-01T12:00:00Z", ValidUntil: "2026-10-01T12:00:20Z"}
  end
  evidence = {Issuer: claims[:iss], Environment: "test", TokenID: claims[:jti], Tenant: "tenant",
    Dimensions: dimensions, KeyID: "key", Signature: nil}
  evidence[:Signature] = Base64.strict_encode64(sign.call("golib/shared-issuer-v1/validity\0" + JSON.generate(evidence)))
  document = {public_key: public_key, tokens: variants.transform_values { |c| token.call(c) }, validity: evidence}
  fixture = File.join(output, "openssl-eddsa.json")
  File.binwrite(fixture, JSON.pretty_generate(document) + "\n")
  manifest = {generator: "scripts/generate-shared-issuer-fixtures.rb", generator_sha256: Digest::SHA256.file(__FILE__).hexdigest,
    implementation: version.strip, license: "OpenSSL Apache-2.0; generated fixtures MIT",
    source: "https://github.com/openssl/openssl/tree/openssl-3.6.4",
    fixture: "testdata/shared-issuer/openssl-eddsa.json", fixture_sha256: Digest::SHA256.file(fixture).hexdigest,
    command: "OPENSSL_BIN=<OpenSSL 3.6.4 binary> ruby scripts/generate-shared-issuer-fixtures.rb",
    update: "Regenerate with the pinned independent implementation, review all bindings, then rerun the fixture test and affected gates."}
  File.binwrite(File.join(output, "manifest.json"), JSON.pretty_generate(manifest) + "\n")
ensure
  FileUtils.remove_entry_secure(work) if File.directory?(work)
end
