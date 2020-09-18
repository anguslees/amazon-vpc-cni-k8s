local metadata = std.native("metadata");
local primaryMac = metadata("mac");

//local v6prefix = metadata("network/interfaces/macs/%s/ipv6-prefix" % primaryMac);
local v6prefix = importstr "/my-prefix";

{
  cniVersion: "0.3.1",
  name: "aws-ipv6-pd",
  plugins: [
    {
      type: "ptp",
      mtu: 9001,
      ipam: {
        type: "host-local",
        ranges: [[{
          subnet: v6prefix,
          //FIXME: rangeStart: .4, (defaults to .2)
          //rangeEnd: something big (defaults to .255)
        }]],
        routes: [{dst: "::/0"}],
        dataDir: "/run/cni/v6pd/ipam",
      },
    },
    {
      type: "egress-v4",
      snatIP: metadata("local-ipv4"),
      ipam: {
        type: "host-local",
        ranges: [[{
          subnet: "100.64.0.0/10",
        }]],
        routes: [{dst: "0.0.0.0/0"}],
        dataDir: "/run/cni/v6pd/egress-v4-ipam",
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
