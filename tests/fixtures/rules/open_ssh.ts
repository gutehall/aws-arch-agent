new ec2.SecurityGroup(this, "SG", {
  allowAllOutbound: true,
  allowAllIpv6Outbound: true,
});
// 0.0.0.0/0 port 22
