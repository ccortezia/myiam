#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { MyIamCdkStack } from '../lib/myiam-cdk-stack';

const app = new cdk.App();
new MyIamCdkStack(app, 'MyIamCdkStack');
