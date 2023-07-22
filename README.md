# Lambda IPS - Automating Network Access List Creation for AWS GuardDuty Alerts


## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Deployment](#deployment)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Customization](#customization)
- [Alert Types Supported](#alert-types-supported)
- [Integration with Slack and Email](#integration-with-slack-and-email)
- [Contributing](#contributing)
## Introduction

Lambda IPS is a powerful Python tool designed to automate network access list creation in response to AWS GuardDuty alerts. GuardDuty is an intelligent threat detection service that continuously monitors for malicious activity and unauthorized behavior within your AWS environment. When GuardDuty detects an alert, Lambda IPS swiftly responds by generating access lists to mitigate the identified threats automatically.

Network security is a critical aspect of any cloud infrastructure, and Lambda IPS aims to simplify the process of implementing effective security measures in real-time.

## Features

- **Automated Access List Creation**: Lambda IPS automatically generates network access lists based on AWS GuardDuty alerts, reducing manual intervention and response time.

- **GuardDuty Integration**: Seamlessly integrates with AWS GuardDuty to receive real-time alerts and take action.

- **Flexible Configuration**: Supports two types of alerts - PortProbeUnprotectedPort and SSHBruteForce, and is easily customizable to handle additional alert types.

- **Highly Scalable**: Built on AWS Lambda, the solution is highly scalable to cater to various workload sizes.

- **Secure and Efficient**: IAM permissions are carefully managed to ensure secure and controlled access for the Lambda function.

- **Slack and Email Notifications**: Optional integration with Slack and Email notifications for enhanced Intrusion Detection System (IDS) capabilities.

## Deployment

To deploy Lambda IPS, follow these steps:

1. Create a new lambda function with Python runtime (>v3.7).
2. Copy and paste the content of the "main.py" file into the lambda function.
3. Assign the necessary IAM permissions to the lambda function. The assigned policy should allow the creation of NACL ingress rules and CloudWatch put log operations.
4. Enable GuardDuty and configure AWS EventBridge to deliver GuardDuty findings to SNS.
5. Subscribe the lambda function to the SNS topic created in the previous step.
6. Optionally, create a Slack group and perform an email SNS subscription using the Slack group email address to deliver alerts to Slack (IDS).

## Getting Started

To get started with Lambda IPS, follow these steps:

1. Clone this repository to your local machine.
2. Open the terminal and navigate to the repository directory.
3. Install the required dependencies by running: `pip install -r requirements.txt`.
4. Customize the configuration settings in the `config.yaml` file according to your requirements.

## Usage

Lambda IPS is designed to run as a serverless AWS Lambda function, automatically triggered by GuardDuty alerts. Once deployed, there is no need for manual execution, as the function will handle alerts and access list creation seamlessly.

## Customization

Lambda IPS can be easily customized to fit your specific use case. The `config.yaml` file provides options for adjusting various settings, such as handling additional alert types or customizing the generated access lists.

## Alert Types Supported

Lambda IPS currently supports the following AWS GuardDuty alert types:

1. PortProbeUnprotectedPort
2. SSHBruteForce

## Integration with Slack and Email

Lambda IPS can be integrated with Slack and Email for enhanced Intrusion Detection System (IDS) capabilities. By subscribing to SNS topics with appropriate configurations, you can receive real-time notifications on Slack channels or email addresses.

## Contributing

I welcome contributions from the community! If you find any issues or have ideas for improvements, please feel free to submit a pull request or open an issue on the GitHub repository.
