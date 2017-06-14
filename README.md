elb audit
============================
This composite monitors elb and reports best practice violations, standards body policy violations, and inventory


## Description
This composite monitors elb against best practices and reports violations and inventory


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_ELB_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_ELB_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_ELB_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_ELB_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are elb-inventory elb-old-ssl-policy elb-current-ssl-policy
  * default: elb-old-ssl-policy, elb-current-ssl-policy, elb-load-balancers-active-security-groups-list

### `AUDIT_AWS_ELB_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of owner of the ELB object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_ELB_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifiers. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Inventory
1. elb


## Categories
1. AWS Services Audit


## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-elb/master/images/icon.png "icon")

