local objectValues(obj) = [obj[k] for k in std.objectFields(obj)];
local objectItems(obj) = [[k, obj[k]] for k in std.objectFields(obj)];

local regions = {
  default: {
    version:: "latest", // or eg "v1.6.2"
    ecrRegion:: "us-west-2",
    ecrAccount:: "602401143452",
    ecrDomain:: "amazonaws.com",
    ecrRepo:: "%s.dkr.ecr.%s.%s" % [self.ecrAccount, self.ecrRegion, self.ecrDomain],
  },

  "us-gov-east-1": self.default {
    ecrRegion: "us-gov-east-1",
    ecrAccount: "151742754352",
  },

  "us-gov-west-1": self.default {
    ecrRegion: "us-gov-west-1",
    ecrAccount: "013241004608",
  },

  "cn": self.default {
    ecrRegion: "cn-northwest-1",
    ecrAccount: "961992271922",
    ecrDomain: "amazonaws.com.cn",
  },
};

local awsnode = {
  clusterRole: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: {name: "aws-node"},
    rules: [
      {
        apiGroups: ["crd.k8s.amazonaws.com"],
        resources: ["eniconfigs"],
        verbs: ["get", "list", "watch"],
      },
      {
        apiGroups: [""],
        resources: ["pods", "namespaces"],
        verbs: ["list", "watch", "get"],
      },
      {
        apiGroups: [""],
        resources: ["nodes"],
        verbs: ["list", "watch", "get", "update"],
      },
      {
        apiGroups: ["extensions"],
        resources: ["*"],
        verbs: ["list", "watch"],
      }
    ],
  },

  serviceAccount: {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "aws-node",
      namespace: "kube-system",
    },
  },

  binding: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: {
      name: "aws-node",
    },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: $.clusterRole.kind,
      name: $.clusterRole.metadata.name,
    },
    subjects: [{
      kind: $.serviceAccount.kind,
      name: $.serviceAccount.metadata.name,
      namespace: $.serviceAccount.metadata.namespace,
    }],
  },

  daemonset: {
    kind: "DaemonSet",
    apiVersion: "apps/v1",
    metadata: {
      name: "aws-node",
      namespace: "kube-system",
      labels: {
        "k8s-app": "aws-node",
      },
    },
    spec: {
      local spec = self,
      updateStrategy: {
        type: "RollingUpdate",
        rollingUpdate: {maxUnavailable: "10%"},
      },
      selector: {
        matchLabels: spec.template.metadata.labels,
      },
      template: {
        metadata: {
          labels: {
            "k8s-app": "aws-node",
          },
        },
        spec: {
          priorityClassName: "system-node-critical",
          terminationGracePeriodSeconds: 10,
          affinity: {
            nodeAffinity: {
              requiredDuringSchedulingIgnoredDuringExecution: {
                nodeSelectorTerms: [
                  {
                    matchExpressions: [
                      {
                        key: "cni",
                        operator: "DoesNotExist",
                      },
                      {
                        key: prefix + "kubernetes.io/os",
                        operator: "In",
                        values: ["linux"],
                      },
                      {
                        key: prefix + "kubernetes.io/arch",
                        operator: "In",
                        values: ["amd64", "arm64"],
                      },
                      {
                        key: "eks.amazonaws.com/compute-type",
                        operator: "NotIn",
                        values: ["fargate"],
                      },
                    ],
                  } for prefix in ["beta.", ""]
                ],
              },
            },
          },
          serviceAccountName: $.serviceAccount.metadata.name,
          hostNetwork: true,
          tolerations: [{operator: "Exists"}],
          containers_:: {
            awsnode: {
              image: "%s/amazon-k8s-cni:%s" % [$.ecrRepo, $.version],
              imagePullPolicy: "Always",
              ports: [{
                containerPort: 61678,
                name: "metrics"
              }],
              name: "aws-node",
              readinessProbe: {
                exec: {
                  command: ["/app/grpc-health-probe", "-addr=:50051"],
                },
                initialDelaySeconds: 1,
              },
              livenessProbe: self.readinessProbe + {
                initialDelaySeconds: 60,
              },
              env_:: {
                ADDITIONAL_ENI_TAGS: "{}",
                AWS_VPC_CNI_NODE_PORT_SUPPORT: "true",
                AWS_VPC_ENI_MTU: "9001",
                AWS_VPC_K8S_CNI_CONFIGURE_RPFILTER: "false",
                AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG: "false",
                AWS_VPC_K8S_CNI_EXTERNALSNAT: "false",
                AWS_VPC_K8S_CNI_LOGLEVEL: "DEBUG",
                AWS_VPC_K8S_CNI_LOG_FILE: "/host/var/log/aws-routed-eni/ipamd.log",
                AWS_VPC_K8S_CNI_RANDOMIZESNAT: "prng",
                AWS_VPC_K8S_CNI_VETHPREFIX: "eni",
                AWS_VPC_K8S_PLUGIN_LOG_FILE: "/var/log/aws-routed-eni/plugin.log",
                AWS_VPC_K8S_PLUGIN_LOG_LEVEL: "DEBUG",
                DISABLE_INTROSPECTION: "false",
                DISABLE_METRICS: "false",
                ENABLE_POD_ENI: "false",
                MY_NODE_NAME: {
                  valueFrom: {
                    fieldRef: {fieldPath: "spec.nodeName"},
                  },
                },
                WARM_ENI_TARGET: "1",
              },
              env: [
                {name: kv[0]} + if std.isObject(kv[1]) then kv[1] else {value: kv[1]}
                for kv in objectItems(self.env_)
              ],
              resources: {
                requests: {cpu: "10m"},
              },
              securityContext: {
                capabilities: {add: ["NET_ADMIN"]},
              },
              volumeMounts: [
                {mountPath: "/host/opt/cni/bin", name: "cni-bin-dir"},
                {mountPath: "/host/etc/cni/net.d", name: "cni-net-dir"},
                {mountPath: "/host/var/log/aws-routed-eni", name: "log-dir"},
                {mountPath: "/var/run/aws-node", name: "run-dir"},
                {mountPath: "/var/run/dockershim.sock", name: "dockershim"},
                {mountPath: "/run/xtables.lock", name: "xtables-lock"},
              ],
            },
          },
          containers: objectValues(self.containers_),
          volumes: [
            {name: "cni-bin-dir", hostPath: {path: "/opt/cni/bin"}},
            {name: "cni-net-dir", hostPath: {path: "/etc/cni/net.d"}},
            {name: "dockershim", hostPath: {path: "/var/run/dockershim.sock"}},
            {name: "xtables-lock", hostPath: {path: "/run/xtables.lock"}},
            {name: "log-dir",
              hostPath: {
                path: "/var/log/aws-routed-eni",
                type: "DirectoryOrCreate",
              },
            },
            {name: "run-dir",
              hostPath: {
                path: "/var/run/aws-node",
                type: "DirectoryOrCreate",
              },
            },
          ],
          initContainers: [
            {
              name: "aws-vpc-cni-init",
              image: "%s/amazon-k8s-cni-init:%s" % [$.ecrRepo, $.version],
              imagePullPolicy: "Always",
              securityContext: {privileged: true},
              env: [
                {
                  name: "DISABLE_TCP_EARLY_DEMUX", value: "false",
                },
              ],
              volumeMounts: [
                {mountPath: "/host/opt/cni/bin", name: "cni-bin-dir"},
              ],
            },
          ],
        },
      },
    },
  },

  crd: {
    apiVersion: "apiextensions.k8s.io/v1beta1",
    kind: "CustomResourceDefinition",
    metadata: {
      name: "eniconfigs.crd.k8s.amazonaws.com",
    },
    spec: {
      scope: "Cluster",
      group: "crd.k8s.amazonaws.com",
      versions: [{
        name: "v1alpha1",
        served: true,
        storage: true,
      }],
      names: {
        plural: "eniconfigs",
        singular: "eniconfig",
        kind: "ENIConfig",
      },
    },
  },
};

local metricsHelper = {
  clusterRole: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: {
      name: "cni-metrics-helper",
    },
    rules: [
      {
        apiGroups: [""],
        resources: [
          "nodes",
          "pods",
          "pods/proxy",
          "services",
          "resourcequotas",
          "replicationcontrollers",
          "limitranges",
          "persistentvolumeclaims",
          "persistentvolumes",
          "namespaces",
          "endpoints",
        ],
        verbs: ["list", "watch", "get"],
      },
      {
        apiGroups: ["extensions"],
        resources: ["daemonsets", "deployments", "replicasets"],
        verbs: ["list", "watch"],
      },
      {
        apiGroups: ["apps"],
        resources: ["statefulsets"],
        verbs: ["list", "watch"],
      },
      {
        apiGroups: ["batch"],
        resources: ["cronjobs", "jobs"],
        verbs: ["list", "watch"],
      },
      {
        apiGroups: ["autoscaling"],
        resources: ["horizontalpodautoscalers"],
        verbs: ["list", "watch"],
      },
    ],
  },

  serviceAccount: {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "cni-metrics-helper",
      namespace: "kube-system",
    },
  },

  binding: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: {
      name: "cni-metrics-helper",
    },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: $.clusterRole.kind,
      name: $.clusterRole.metadata.name,
    },
    subjects: [{
      kind: $.serviceAccount.kind,
      name: $.serviceAccount.metadata.name,
      namespace: $.serviceAccount.metadata.namespace,
    }],
  },

  deployment: {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: {
      name: "cni-metrics-helper",
      namespace: "kube-system",
      labels: {
        "k8s-app": "cni-metrics-helper",
      },
    },
    spec: {
      local spec = self,
      selector: {
        matchLabels: spec.template.metadata.labels,
      },
      template: {
        metadata: {
          labels: {
            "k8s-app": "cni-metrics-helper",
          },
        },
        spec: {
          serviceAccountName: $.serviceAccount.metadata.name,
          containers_:: {
            metricshelper: {
              image: "%s/cni-metrics-helper:%s" % [$.ecrRepo, $.version],
              imagePullPolicy: "Always",
              name: "cni-metrics-helper",
              env_:: {
                USE_CLOUDWATCH: "true",
              },
              env: [
                {name: kv[0]} + if std.isObject(kv[1]) then kv[1] else {value: kv[1]}
                for kv in objectItems(self.env_)
              ],
            },
          },
          containers: objectValues(self.containers_),
        },
      },
    },
  },
};

local imdsCni = {
  daemonset: {
    kind: "DaemonSet",
    apiVersion: "apps/v1",
    local name = "aws-imds-cni",
    metadata: {
      name: name,
      namespace: "kube-system",
      labels: {"k8s-app": name},
    },
    spec: {
      local spec = self,
      updateStrategy: {
        type: "RollingUpdate",
        rollingUpdate: {maxUnavailable: "10%"},
      },
      selector: {
        matchLabels: spec.template.metadata.labels,
      },
      template: {
        metadata: {
          labels: {"k8s-app": name},
        },
        spec: {
          priorityClassName: "system-node-critical",
          terminationGracePeriodSeconds: 10,
          affinity: {
            nodeAffinity: {
              requiredDuringSchedulingIgnoredDuringExecution: {
                nodeSelectorTerms: [
                  {
                    matchExpressions: [
                      {
                        key: "cni",
                        operator: "In",
                        values: ["aws-imds-cni"],
                      },
                      {
                        key: prefix + "kubernetes.io/os",
                        operator: "In",
                        values: ["linux"],
                      },
                      {
                        key: prefix + "kubernetes.io/arch",
                        operator: "In",
                        values: ["amd64"],
                      },
                      {
                        key: "eks.amazonaws.com/compute-type",
                        operator: "NotIn",
                        values: ["fargate"],
                      },
                    ],
                  } for prefix in ["beta.", ""]
                ],
              },
            },
          },

          hostNetwork: true,
          automountServiceAccountToken: false,
          tolerations: [
            {effect: "NoSchedule", operator: "Exists", key: "node.kubernetes.io/not-ready"},
          ],

          volumes: [
            {
              name: "cni-bin-dir",
              hostPath: {path: "/opt/cni/bin", type: "DirectoryOrCreate"},
            },
            {
              name: "cni-net-dir",
              hostPath: {path: "/etc/cni/net.d", type: "DirectoryOrCreate"},
            },
          ],
          initContainers: [
            {
              name: "conf",
              image: "%s/amazon-v6pd-cni-init:%s" % [$.ecrRepo, $.version],
              local configTemplate = importstr "imds-cni.jsonnet",
              command: ["/bin/sh", "-x", "-e", "-c", self.shcmd],
              shcmd:: |||
                ./attach-enis
                install -m755 imds-ipam imds-ptp bandwidth portmap ptp /opt/cni/bin
                ./json-tmpl --file=- -v=4 --logtostderr >/etc/cni/net.d/10-aws.conflist <<'EOF'
                %sEOF
              ||| % configTemplate,
              env_:: {
                AWS_VPC_K8S_CNI_LOGLEVEL: "Debug",
                AWS_VPC_K8S_CNI_LOG_FILE: "stdout",
              },
              env: [
                {name: kv[0]} + if std.isObject(kv[1]) then kv[1] else {value: kv[1]}
                for kv in objectItems(self.env_)
              ],
              volumeMounts: [
                {mountPath: "/opt/cni/bin", name: "cni-bin-dir"},
                {mountPath: "/etc/cni/net.d", name: "cni-net-dir"},
              ],
            },
          ],

          containers_:: {
            pause: {
              name: "pause",
              image: "%s/eks/pause-amd64:3.1" % $.ecrRepo,
            }
          },
          containers: objectValues(self.containers_),
        },
      },
    },
  },
};

local v6pd = {
  daemonset: {
    kind: "DaemonSet",
    apiVersion: "apps/v1",
    // NB: intentionally conflicts with awsnode.daemonset above.
    // Can only have one installed, and this allows in-place switching.
    // It doesn't have to be this way though, they could co-exist in
    // the same cluster based on nodeSelectors, etc.
    //local name = "aws-v6pd",
    local name = "aws-node",
    metadata: {
      name: name,
      namespace: "kube-system",
      labels: {
        "k8s-app": name,
      },
    },
    spec: {
      local spec = self,
      updateStrategy: {
        type: "RollingUpdate",
        rollingUpdate: {maxUnavailable: "10%"},
      },
      selector: {
        matchLabels: spec.template.metadata.labels,
      },
      template: {
        metadata: {
          labels: {
            "k8s-app": name,
          },
        },
        spec: {
          priorityClassName: "system-node-critical",
          terminationGracePeriodSeconds: 10,
          affinity: {
            nodeAffinity: {
              requiredDuringSchedulingIgnoredDuringExecution: {
                nodeSelectorTerms: [
                  {
                    matchExpressions: [
                      {
                        key: prefix + "kubernetes.io/os",
                        operator: "In",
                        values: ["linux"],
                      },
                      {
                        key: prefix + "kubernetes.io/arch",
                        operator: "In",
                        values: ["amd64"],
                      },
                      {
                        key: "eks.amazonaws.com/compute-type",
                        operator: "NotIn",
                        values: ["fargate"],
                      },
                    ],
                  } for prefix in ["beta.", ""]
                ],
              },
            },
          },

          hostNetwork: true,
          automountServiceAccountToken: false,
          tolerations: [
            {effect: "NoSchedule", operator: "Exists", key: "node.kubernetes.io/not-ready"},
          ],

          volumes: [
            {
              name: "cni-bin-dir",
              hostPath: {path: "/opt/cni/bin", type: "DirectoryOrCreate"},
            },
            {
              name: "cni-net-dir",
              hostPath: {path: "/etc/cni/net.d", type: "DirectoryOrCreate"},
            },
            {
              name: "my-prefix",
              hostPath: {path: "/run/fake-pd/my-prefix", type: "File"},
            },
          ],

          initContainers: [{
            name: "conf",
            image: "%s/amazon-v6pd-cni-init:%s" % [$.ecrRepo, $.version],
            local v6pd_template = importstr "v6pd.jsonnet",
            command: ["/bin/sh", "-x", "-e", "-c", self.shcmd],
            shcmd:: |||
              install -m755 host-local bandwidth portmap ptp egress-v4 /opt/cni/bin
              ./json-tmpl --file=- -v=4 --logtostderr >/etc/cni/net.d/10-aws.conflist <<'EOF'
              %sEOF
            ||| % v6pd_template,
            volumeMounts: [
              {mountPath: "/opt/cni/bin", name: "cni-bin-dir"},
              {mountPath: "/etc/cni/net.d", name: "cni-net-dir"},
              {mountPath: "/my-prefix", name: "my-prefix", readOnly: true},
            ],
          }],

          containers_:: {
            pause: {
              name: "pause",
              image: "%s/eks/pause-amd64:3.1" % $.ecrRepo,
            }
          },
          containers: objectValues(self.containers_),
        },
      },
    },
  },

  // This just "fakes" what Prefix Delegation would do, for testing.
  // It is not necessary once Prefix Delegation launches.
  fakepd: {
    kind: "DaemonSet",
    apiVersion: "apps/v1",
    metadata: {
      name: "fake-pd",
      namespace: "kube-system",
      labels: {
        "k8s-app": "fake-pd",
      },
    },
    spec: {
      local spec = self,
      updateStrategy: {
        type: "RollingUpdate",
        rollingUpdate: {maxUnavailable: "10%"},
      },
      selector: {
        matchLabels: spec.template.metadata.labels,
      },
      template: {
        metadata: {
          labels: {
            "k8s-app": "fake-pd",
          },
        },
        spec: {
          priorityClassName: "system-node-critical",
          terminationGracePeriodSeconds: 1,
          hostNetwork: true,
          tolerations: [
            {effect: "NoSchedule", operator: "Exists", key: "node.kubernetes.io/not-ready"},
          ],
          serviceAccountName: $.fakepdAccount.metadata.name,

          volumes: [
            {
              name: "confdir",
              hostPath: {path: "/run/fake-pd", type: "DirectoryOrCreate"},
            },
          ],

          containers_:: {
            pd: {
              // Poor-man's route broadcast (this is basically flannel host-gw)
              name: "pd",
              image: "amazon/aws-cli:2.0.53",
              command: ["/bin/sh", "-x", "-e", "-c", self.shcmd],
              shcmd:: |||
                metadata() {
                  curl -q http://169.254.169.254/2019-10-01/meta-data/$1
                }
                ip6cidr() {
                  # This is a randomly chosen ULA (/48), subnet 0 (/64), with embedded v4 address (/104).  Note bits 64-71 must be zero because RFC4291.
                  IFS=.; printf "fd47:6d80:fb79:0:%02x:%02x%02x:%02x00::/104" $1; IFS=
                }

                #myip=$(metadata network/interfaces/macs/$(metadata mac)/ipv6s)
                mypfx=$(ip6cidr $(metadata local-ipv4))
                ifid=$(metadata network/interfaces/macs/$(metadata mac)/interface-id)

                echo -n $mypfx > /conf/my-prefix

                aws ec2 modify-network-interface-attribute --no-source-dest-check --network-interface-id $ifid
                for id in $ROUTE_TABLES; do
                  aws ec2 create-route --route-table-id $id --destination-ipv6-cidr-block $mypfx --network-interface-id $ifid ||
                  aws ec2 replace-route --route-table-id $id --destination-ipv6-cidr-block $mypfx --network-interface-id $ifid
                done

                while :; do
                  sleep 86400
                done
              |||,
              env_:: {
                ROUTE_TABLES: "@ROUTE_TABLES@",
              },
              env: [
                {name: kv[0]} + if std.isObject(kv[1]) then kv[1] else {value: kv[1]}
                for kv in objectItems(self.env_)
              ],
              securityContext: {
                capabilities: {add: ["NET_ADMIN"]},
                // Ensure we can write to /run/fake-pd
                runAsUser: 0,
              },
              volumeMounts: [
                {name: "confdir", mountPath: "/conf", readOnly: false},
              ],
            },
          },
          containers: objectValues(self.containers_),
        },
      },
    },
  },

  fakepdAccount: {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "fake-pd",
      namespace: "kube-system",
      annotations: {
        "eks.amazon.com/role-arn": "@FAKEPD_ROLE@",
      },
    },
  },

  fakepdRole: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: {name: "fake-pd"},
    rules: [
      {
        apiGroups: [""],
        resources: ["nodes"],
        verbs: ["list", "get", "update", "patch"],
      },
    ],
  },

  fakepdBinding: {
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: {
      name: "fake-pd",
    },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: $.fakepdRole.kind,
      name: $.fakepdRole.metadata.name,
    },
    subjects: [{
      kind: $.fakepdAccount.kind,
      name: $.fakepdAccount.metadata.name,
      namespace: $.fakepdAccount.metadata.namespace,
    }],
  },
};

local byRegion(basename, template) = {
  [
    basename + (if kv[0] == "default" then "" else "-" + kv[0])
  ]: template + kv[1]
  for kv in objectItems(regions)
};

// Output values, as jsonnet objects
local output =
byRegion("aws-k8s-cni", awsnode) +
byRegion("cni-metrics-helper", metricsHelper) +
byRegion("imds-cni", imdsCni) +
byRegion("v6pd-cni", v6pd);

// Yaml-ified output values
{
  [kv[0] + ".yaml"]: std.manifestYamlStream(objectValues(kv[1]))
  for kv in objectItems(output)
}
