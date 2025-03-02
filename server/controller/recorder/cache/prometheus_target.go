/**
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

package cache

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DiffBaseDataSet) addPrometheusTarget(dbItem *mysql.PrometheusTarget, seq int) {
	b.PrometheusTarget[dbItem.Lcuuid] = &PrometheusTarget{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Instance:    dbItem.Instance,
		Job:         dbItem.Job,
		ScrapeURL:   dbItem.ScrapeURL,
		OtherLabels: dbItem.OtherLabels,
	}
	log.Info(addDiffBase(ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, b.PrometheusTarget[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePrometheusTarget(lcuuid string) {
	delete(b.PrometheusTarget, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, lcuuid))
}

type PrometheusTarget struct {
	DiffBase
	Instance    string `json:"instance" binding:"required"`
	Job         string `json:"job" binding:"required"`
	ScrapeURL   string `json:"scrape_url" binding:"required"`
	OtherLabels string `json:"other_labels" binding:"required"`
}

func (p *PrometheusTarget) Update(cloudItem *cloudmodel.PrometheusTarget) {
	p.Instance = cloudItem.Instance
	p.Job = cloudItem.Job
	p.ScrapeURL = cloudItem.ScrapeURL
	p.OtherLabels = cloudItem.OtherLabels
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, p))
}
