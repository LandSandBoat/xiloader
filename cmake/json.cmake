CPMAddPackage(
  NAME nlohmann_json
  GITHUB_REPOSITORY nlohmann/json
  GIT_TAG v3.12.0
  OPTIONS
    "JSON_ImplicitConversions OFF" #Recommended by the author
    "JSON_BuildTests OFF"
)
