#!/usr/bin/env node
const { Stack, App } = require("aws-cdk-lib");

class MinimalStack extends Stack {
  constructor(scope: any, id: string) {
    super(scope, id);
  }
}

const app = new App();
new MinimalStack(app, "MinimalStack");
app.synth();
