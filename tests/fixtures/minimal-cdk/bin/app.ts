#!/usr/bin/env node
const cdk = require('aws-cdk-lib');
const { Stack, App } = require('aws-cdk-lib');

class MinimalStack extends Stack {
  constructor(scope, id) {
    super(scope, id);
  }
}

const app = new App();
new MinimalStack(app, 'MinimalStack');
app.synth();
