{
  cniVersion: "0.3.1",
  name: "aws-vpc",
  plugins: [
    {
      type: "imds-ptp",
      mtu: 9001,
      ipam: {
        type: "imds-ipam",
        routes: [{dst: "0.0.0.0/0"}],
        dataDir: "/run/cni/ipam",
      },
    },
    {
      type: "portmap",
      capabilities: {portMappings: true},
    },
    {
      type: "bandwidth",
      capabilities: {bandwidth: true},
    },
  ],
}
