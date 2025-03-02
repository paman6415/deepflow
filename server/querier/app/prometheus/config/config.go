/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

type Prometheus struct {
	Limit                   string          `default:"1000000" yaml:"limit"`
	QPSLimit                int             `default:"100" yaml:"qps-limit"`
	SeriesLimit             int             `default:"500" yaml:"series-limit"`
	MaxSamples              int             `default:"50000000" yaml:"max-samples"`
	AutoTaggingPrefix       string          `default:"df_" yaml:"auto-tagging-prefix"`
	RequestQueryWithDebug   bool            `default:"false" yaml:"request-query-with-debug"`
	ExternalTagCacheSize    int             `default:"1024" yaml:"external-tag-cache-size"`
	ExternalTagLoadInterval int             `default:"300" yaml:"external-tag-load-interval"`
	ThanosReplicaLabels     []string        `yaml:"thanos-replica-labels"`
	Cache                   PrometheusCache `yaml:"cache"`
}

type PrometheusCache struct {
	Enabled                bool    `default:"false" yaml:"enabled"`
	CacheItemSize          uint64  `default:"51200000" yaml:"cache-item-size"` // cache-item-size for each cache item, default: 50M
	CacheMaxCount          int     `default:"1024" yaml:"cache-max-count"`     // cache-max-count for list of cache size
	CacheMaxAllowDeviation float64 `default:"3600" yaml:"cache-max-allow-deviation"`
}
