benchmark "benchmark_categories" {
  title         = "Benchmark Categories"
  description   = "An implementation of the nine defined benchmark categories."
  documentation = file("./docs/overview.md")
  children = [
    benchmark.access_to_fs,
  ]
}