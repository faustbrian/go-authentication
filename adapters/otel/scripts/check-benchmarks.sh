#!/usr/bin/env bash
set -euo pipefail

bench_time="${BENCH_TIME:-1000x}"
bench_count="${BENCH_COUNT:-5}"
result="$(mktemp "${TMPDIR:-/tmp}/authentication-adapters-otel-benchmark.XXXXXX")"
trap 'rm -f "${result}"' EXIT

go test ./... \
    -run '^$' \
    -bench '^BenchmarkAuthenticationInstrumentation$' \
    -benchmem \
    -benchtime="${bench_time}" \
    -count="${bench_count}" | tee "${result}"

median_field() {
    local mode="$1"
    local field="$2"
    awk -v mode="/${mode}-" -v field="${field}" \
        'index($1, mode) > 0 { print $field }' "${result}" |
        sort -n |
        awk '
        END {
            if (NR == 0) exit 1
            if (NR % 2 == 1) printf "%.6f\n", values[(NR + 1) / 2]
            else printf "%.6f\n", (values[NR / 2] + values[NR / 2 + 1]) / 2
        }
        { values[NR] = $1 }
    '
}

direct_latency="$(median_field direct 3)"
direct_allocations="$(median_field direct 7)"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
goversion="$(go env GOVERSION)"
cpu="$(awk -F ': ' '$1 == "cpu" { print $2; exit }' "${result}")"

printf 'benchmark_environment goos=%s goarch=%s goversion=%s cpu=%s\n' \
    "${goos}" "${goarch}" "${goversion}" "${cpu:-unknown}"
printf 'benchmark_method statistic=median samples=%s benchtime=%s corpus=direct,opentelemetry_noop,opentelemetry_sampled_out,opentelemetry_enabled\n' \
    "${bench_count}" "${bench_time}"
printf 'direct median_ns=%s throughput_ops_per_second=%.2f median_allocs=%s\n' \
    "${direct_latency}" \
    "$(awk -v latency="${direct_latency}" 'BEGIN { print 1000000000 / latency }')" \
    "${direct_allocations}"

check_budget() {
    local mode="$1"
    local latency_multiple="$2"
    local allocation_limit="$3"
    local latency allocations latency_limit latency_multiple_actual throughput failed

    latency="$(median_field "${mode}" 3)"
    allocations="$(median_field "${mode}" 7)"
    latency_limit="$(awk -v direct="${direct_latency}" -v multiple="${latency_multiple}" \
        'BEGIN { print direct * multiple }')"
    latency_multiple_actual="$(awk -v actual="${latency}" -v direct="${direct_latency}" \
        'BEGIN { print actual / direct }')"
    throughput="$(awk -v latency="${latency}" 'BEGIN { print 1000000000 / latency }')"
    failed=0

    printf '%s median_ns=%s throughput_ops_per_second=%.2f direct_multiple=%.2f median_allocs=%s\n' \
        "${mode}" "${latency}" "${throughput}" "${latency_multiple_actual}" "${allocations}"

    awk -v actual="${latency}" -v limit="${latency_limit}" \
        'BEGIN { if (actual > limit) exit 1 }' || {
        printf '%s latency budget exceeded: actual_ns=%s direct_ns=%s actual_multiple=%.2f limit_multiple=%.0f limit_ns=%s\n' \
            "${mode}" "${latency}" "${direct_latency}" "${latency_multiple_actual}" \
            "${latency_multiple}" "${latency_limit}" >&2
        failed=1
    }
    awk -v actual="${allocations}" -v limit="${allocation_limit}" \
        'BEGIN { if (actual > limit) exit 1 }' || {
        printf '%s allocation budget exceeded: actual_allocs=%s direct_allocs=%s limit_allocs=%.0f\n' \
            "${mode}" "${allocations}" "${direct_allocations}" "${allocation_limit}" >&2
        failed=1
    }
    if ((failed != 0)); then
        return 1
    fi
}

check_budget opentelemetry_noop 100 20
check_budget opentelemetry_sampled_out 150 22
check_budget opentelemetry_enabled 200 24
