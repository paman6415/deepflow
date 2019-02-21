package mapreduce

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type HandlerCounter struct {
	flowCounter uint64
	dropCounter uint64
}

type ProcessorCounter struct {
	docCounter       uint64
	emitCounter      uint64
	maxCounter       uint64
	rejectionCounter uint64
	flushCounter     uint64
}

func FillStatItems(items []stats.StatItem, handlerCounter HandlerCounter, processorNames []string, processorCounters []ProcessorCounter) []stats.StatItem {
	if len(processorNames) != len(processorCounters) {
		panic("processor长度不匹配")
	}
	items = append(items, stats.StatItem{
		Name:  "flow_counter",
		Value: handlerCounter.flowCounter,
	})
	items = append(items, stats.StatItem{
		Name:  "drop_counter",
		Value: handlerCounter.dropCounter,
	})
	for i, name := range processorNames {
		counter := processorCounters[i]

		items = append(items, stats.StatItem{
			Name:  name,
			Value: counter.emitCounter,
		})

		avgDoc := uint64(0)
		if handlerCounter.flowCounter != 0 {
			avgDoc = counter.docCounter / handlerCounter.flowCounter
		}
		items = append(items, stats.StatItem{
			Name:  fmt.Sprintf("%s_avg_doc_counter", name),
			Value: avgDoc,
		})

		items = append(items, stats.StatItem{
			Name:  fmt.Sprintf("%s_max_doc_counter", name),
			Value: counter.maxCounter,
		})

		items = append(items, stats.StatItem{
			Name:  fmt.Sprintf("%s_rejected_doc", name),
			Value: counter.rejectionCounter,
		})

		items = append(items, stats.StatItem{
			Name:  fmt.Sprintf("%s_flush", name),
			Value: counter.flushCounter,
		})
	}
	return items
}
