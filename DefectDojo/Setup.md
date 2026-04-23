# DefectDojo Set Up
By following the [official documentation](https://docs.defectdojo.com/get_started/open_source/installation/), DefectDojo can be installed with
- [Linux Service](https://github.com/DefectDojo/godojo.git),(DEPRECATION WARNING, no longer update release)
- [Kubernetes](https://github.com/DefectDojo/django-DefectDojo/blob/dev/helm/defectdojo/README.md), with helm chart
- [Saas](https://defectdojo.com/platform)
- [Docker](https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md)

I will install as docker container
## 1. Install DefectDojo
- Clone Repository
```sh
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
```
-Set Production ENV
```sh
docker/setEnv.sh release
```
- Build images
```sh
docker compose build
```
- Running Container
```sh
docker compose up -d
```
Wait for all container running except **django-defectdojo-initializer-1** must be Exited (do't remove this container, admin credentials in this container logs)

## 2. DefectDojo Api Key and Token
- Login to DefectDojo Dashboard
- Click on profile account, choose API V2 Key
- Copy or regenerate key

## 3. Create DefectDojo Product
```sh
curl -k -X POST "http://$DEFECT_DOJO_SERVER_IP:8080/api/v2/products/" \
  -H "Authorization: Token $DEFECT_DOJO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Wazuh Vulnerability Management",
    "description": "Produk untuk mengelola kerentanan yang ditemukan oleh Wazuh",
    "prod_type": 1
  }'
```
## 4. Create Engagements
```sh
curl -k -X POST "http://$DEFECT_DOJO_SERVER_IP:8080/api/v2/engagements/" \
  -H "Authorization: Token $DEFECT_DOJO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Wazuh VA - Test Agent",
    "product": 1,
    "target_start": "2026-04-22",
    "target_end": "2026-05-22",
    "engagement_type": "CI/CD",
    "status": "In Progress"
  }'
```