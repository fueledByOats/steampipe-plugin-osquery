benchmark "get_runtime_information_about_os_components" {
  title         = "3 Get Runtime Information About OS Components"
  documentation = file("./docs/3_get_runtime_information_about_os_components.md")
  children = [
    control.check_permissions_on_etc_issue,
  ]
}