//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "gocloud.dev/blob/fileblob" // fileblob
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/pubsub/kafkapubsub"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gocloud.dev/pubsub"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/log"
)

const rekorSthPubSubTopicEnv = "REKOR_STH_TOPIC"

// watchKafkaCmd represents the serve command
var watchKafkaCmd = &cobra.Command{
	Use:   "watch_kafka",
	Short: "Start a process to watch and record STH's from Rekor",
	Long:  `Start a process to watch and record STH's from Rekor`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Logger.Fatal("Error initializing cmd line args: ", err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		// Setup the logger to dev/prod
		log.ConfigureLogger(viper.GetString("log_type"))

		// workaround for https://github.com/sigstore/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		host := viper.GetString("rekor_server.address")
		port := viper.GetUint("rekor_server.port")
		interval := viper.GetDuration("interval")
		url := fmt.Sprintf("http://%s:%d", host, port)
		c, err := app.GetRekorClient(url)
		if err != nil {
			return err
		}

		keyResp, err := c.Pubkey.GetPublicKey(nil)
		if err != nil {
			return err
		}
		publicKey := keyResp.Payload
		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return errors.New("failed to decode public key of server")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}

		ctx := context.Background()
		topicURL := os.Getenv(rekorSthPubSubTopicEnv)
		if topicURL == "" {
			log.CliLogger.Fatalf("%s env var must be set", rekorSthPubSubTopicEnv)
		}

		topic, err := pubsub.OpenTopic(ctx, topicURL)
		if err != nil {
			return err
		}
		defer topic.Shutdown(ctx)
		tick := time.NewTicker(interval)
		var last *SignedAndUnsignedLogRoot

		for {
			<-tick.C
			log.Logger.Info("performing check")
			lr, err := doCheck(c, pub)
			if err != nil {
				log.Logger.Warnf("error verifiying tree: %s", err)
				continue
			}
			log.Logger.Infof("Found and verified state at %d %d", lr.VerifiedLogRoot.TreeSize, lr.VerifiedLogRoot.TimestampNanos)
			if last != nil && last.VerifiedLogRoot.TreeSize == lr.VerifiedLogRoot.TreeSize {
				log.Logger.Infof("Last tree size is the same as the current one: %d %d",
					last.VerifiedLogRoot.TreeSize, lr.VerifiedLogRoot.TreeSize)
				// If it's the same, it shouldn't have changed but we'll still upload anyway
				// in case that failed.
			}

			if err := uploadToKafka(ctx, topic, lr); err != nil {
				log.Logger.Warnf("error uploading result: %s", err)
				continue
			}
			last = lr
		}
	},
}

func init() {
	watchKafkaCmd.Flags().Duration("interval", 1*time.Minute, "Polling interval")
	rootCmd.AddCommand(watchKafkaCmd)
}

func uploadToKafka(ctx context.Context, topic *pubsub.Topic, lr *SignedAndUnsignedLogRoot) error {
	b, err := json.Marshal(lr)
	if err != nil {
		return err
	}

	err = topic.Send(ctx, &pubsub.Message{
		Body: b,
		Metadata: map[string]string{
			"format":       "json",
			"sth-treesize": strconv.FormatUint(lr.VerifiedLogRoot.TreeSize, 10),
		},
	})
	if err != nil {
		return err
	}
	return nil
}
