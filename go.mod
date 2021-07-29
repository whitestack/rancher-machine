module github.com/rancher/machine

go 1.15

replace (
	github.com/docker/docker => github.com/moby/moby v1.4.2-0.20170731201646-1009e6a40b29
	github.com/urfave/cli => github.com/urfave/cli v1.11.1-0.20151120215642-0302d3914d2a // newer versions of this will break the rpc binding code
)

require (
	github.com/Azure/azure-sdk-for-go v55.7.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.19
	github.com/Azure/go-autorest/autorest/adal v0.9.14
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/aws/aws-sdk-go v1.33.14
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/bugsnag/bugsnag-go v0.0.0-20151120182711-02e952891c52
	github.com/bugsnag/osext v0.0.0-20130617224835-0dd3f918b21b // indirect
	github.com/bugsnag/panicwrap v0.0.0-20160118154447-aceac81c6e2f // indirect
	github.com/cenkalti/backoff v0.0.0-20141124221459-9831e1e25c87 // indirect
	github.com/digitalocean/godo v0.0.0-20170317202744-d59ed2fe842b
	github.com/diskfs/go-diskfs v0.0.0-20191115120903-6cf046d472d7
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/exoscale/egoscale v0.12.3
	github.com/form3tech-oss/jwt-go v3.2.3+incompatible // indirect
	github.com/google/go-querystring v0.0.0-20140804062624-30f7a39f4a21 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gophercloud/gophercloud v0.7.0
	github.com/gophercloud/utils v0.0.0-20191129022341-463e26ffa30d
	github.com/gorilla/mux v1.7.3 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/juju/loggo v0.0.0-20190526231331-6e530bcce5d8 // indirect
	github.com/rackspace/gophercloud v0.0.0-20150408191457-ce0f487f6747
	github.com/rancher/wrangler v0.8.1-0.20210506052526-673b7f8692d9
	github.com/samalba/dockerclient v0.0.0-20151231000007-f661dd4754aa
	github.com/skarademir/naturalsort v0.0.0-20150715044055-69a5d87bef62
	github.com/stretchr/testify v1.6.1
	github.com/tent/http-link-go v0.0.0-20130702225549-ac974c61c2f9 // indirect
	github.com/urfave/cli v1.20.0
	github.com/vmware/govcloudair v0.0.2
	github.com/vmware/govmomi v0.23.2-0.20201015235820-81318771d0e0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
	google.golang.org/api v0.20.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/utils v0.0.0-20210111153108-fddb29f9d009 // indirect
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)
