#!/usr/bin/env bats

@test "reject because /data is not in settings" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-hostpaths.json \
    --settings-json \
    '{ "allowedHostPaths": [
           {"pathPrefix": "/var","readOnly": false},
           {"pathPrefix": "/var/local/aaa","readOnly": false}
        ]
     }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*hostPath '/data' mounted as 'test-data' is not in the AllowedHostPaths list.*") -ne 0 ]
}

@test "accept because pod has no hostPath volumes" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-no-hostpaths.json \
    --settings-json \
    '{ "allowedHostPaths": [ {"pathPrefix": "/foo","readOnly": true} ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept because /var/local has precedence over /var" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-precedence.json \
    --settings-json \
    '{ "allowedHostPaths": [
           {"pathPrefix": "/var","readOnly": false},
           {"pathPrefix": "/var/local","readOnly": true}
        ]
     }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
