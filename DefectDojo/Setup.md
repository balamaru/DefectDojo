# DefectDojo Set Up
By following the [official documentation](https://docs.defectdojo.com/get_started/open_source/installation/), DefectDojo can be installed via several methods:
- **Kubernetes**, using the [Helm Chart](https://github.com/DefectDojo/django-DefectDojo/blob/dev/helm/defectdojo/README.md)
- **Saas**, using the [DefectDojo Cloud Platform](https://defectdojo.com/platform)
- **Docker**, using [Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md)
- **Linux Service**,Via [Godojo](https://github.com/DefectDojo/godojo.git), (DEPRECATION WARNING, This method is no longer actively updated)

For this project, we will proceed with the Docker container installation.
## 1. Install DefectDojo via Docker
Follow these steps to deploy DefectDojo:
- Clone Repository
```sh
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
```
- Set the Production Environment
```sh
docker/setEnv.sh release
```
- Build and Run Containers
```sh
# Build the images
docker compose build

# Start the containers in detached mode
docker compose up -d
```
> Note: Wait until all containers are running. The *django-defectdojo-initializer-1* container should eventually show an **Exited** status. **Do not remove this container**, as you will find the initial admin credentials in its logs *docker compose logs django-defectdojo-initializer-1 | grep "Admin password:"*.

## 2. Obtain API v2 Key and Token
- Log in to your DefectDojo Dashboard.
- Click on your Profile icon in the top right corner.
- Select API v2 Key
- Copy your existing key or click Regenerate if needed.

## 3. Create a DefectDojo Product
Use the following API call to create a new product for tracking vulnerabilities:
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
## 4. Create an Engagements
An engagement is required to group specific security tests. You can create one using the command below:
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