module github.com/sigstore/rekor

go 1.14

require (
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/blang/semver v3.5.1+incompatible
	github.com/cavaliercoder/badio v0.0.0-20160213150051-ce5280129e9e // indirect
	github.com/cavaliercoder/go-rpm v0.0.0-20200122174316-8cb9fd9c31a8
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-openapi/errors v0.20.2
	github.com/go-openapi/loads v0.21.1
	github.com/go-openapi/runtime v0.24.0
	github.com/go-openapi/spec v0.20.4
	github.com/go-openapi/strfmt v0.21.2
	github.com/go-openapi/swag v0.21.1
	github.com/go-openapi/validate v0.21.0
	github.com/golang/protobuf v1.4.3
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/rpmpack v0.0.0-20210107155803-d6befbf05148
	github.com/google/trillian v1.3.13
	github.com/jedisct1/go-minisign v0.0.0-20210106175330-e54e81d562c7
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mediocregopher/radix/v4 v4.0.0-beta.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.3
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/rs/cors v1.7.0
	github.com/spf13/afero v1.5.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/urfave/negroni v1.0.0
	go.uber.org/goleak v1.1.10
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/mod v0.4.1 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	golang.org/x/tools v0.1.0 // indirect
	google.golang.org/genproto v0.0.0-20200825200019-8632dd797987
	google.golang.org/grpc v1.36.0
	gopkg.in/ini.v1 v1.62.0 // indirect
	honnef.co/go/tools v0.0.1-2020.1.4 // indirect
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
