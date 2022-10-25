# Enrollment Helper

---

The script/service in this repo is used to create/provision new Elasticsearch and Kibana instances through using an enrollment token.

The code is currently written to run/be included with Elasticsearch instances on EC2's and Kibana instances running in AWS ECS.

Licensed under the Apache 2.0

---
### Process Flow

**Elasticsearch**
1. A new Elasticsearch Instance is stood up and "pings" a list of EC2 Instances marked 'InService' and are part of the same Autoscaling Group.
2. The first remote EC2 Instance that sends a "pong" marks the instance as "up" and "present"
3. Then the new Instance will request a new Enrollment Token
4. Once the new Enrollment Token is generated, it is sent back to the new Instance
5. The new instance uses the Enrollment Token to add itself to the EC2 ASG cluster


**Kibana**
1. A new Kibana instance/task starts up and "pings" a list of EC2 Instances marked 'InService' and are part of the same Autoscaling Group. (An additional container should be used for this initialization)
2. When Kibana receives a "pong" from an EC2 Instance, it then triggers an api served by the Enrollment Helper service on the same EC2 Instance
3. The triggered API will then:
  - Generate an Enrollment Token
  - Search through the logs of the specific Kibana ECS task for a randomly generated auth code
  - Build a request with the Enrollment Token and the found auth code
  - Send the request to a Kibana API, finishing the enrollment
4. Kibana then will autoconfigure itself to the Elasticsearch Instances



___

### Required Environment Variables
These should be stored in a default file named: `/etc/profile.d/es_env_vars`. 

If you change the file location for the environment variables files, you need to change the entry in enrollment_helper.service file too.


**Required Environment Variables**
- `ENROLLMENT_HELPER_SECRET_ARN`  
- `USER_SECRET_ARN`  
- `EC2_ASG_CLUSTER_NAME`  
- `ECS_CLUSTER_NAME`  
- `ECS_TASK_FAMILY_NAME`  


