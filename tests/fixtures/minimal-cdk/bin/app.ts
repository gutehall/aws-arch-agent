#!/usr/bin/env node
import { App, Stack } from "aws-cdk-lib";
import { Construct } from "constructs";

class MinimalStack extends Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id);
  }
}

const app = new App();
new MinimalStack(app, 'MinimalStack');
app.synth();
