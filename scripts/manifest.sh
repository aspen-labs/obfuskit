docker manifest create \
piyushroshan/obfuskit:latest \
--amend piyushroshan/obfuskit:latest-amd64 \
--amend piyushroshan/obfuskit:latest-arm64

docker manifest create piyushroshan/obfuskit-vuln-app:latest \
--amend piyushroshan/obfuskit-vuln-app:latest-amd64 \
--amend piyushroshan/obfuskit-vuln-app:latest-arm64

docker manifest create piyushroshan/obfuskit-coraza-waf:latest \
--amend piyushroshan/obfuskit-coraza-waf:latest-amd64 \
--amend piyushroshan/obfuskit-coraza-waf:latest-arm64

docker manifest push piyushroshan/obfuskit:latest
docker manifest push piyushroshan/obfuskit-vuln-app:latest
docker manifest push piyushroshan/obfuskit-coraza-waf:latest