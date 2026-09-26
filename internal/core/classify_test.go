package core

import "testing"

// One subscriber panicking must not stop the batch reaching the rest.
func TestFlowBusContainsAPanickingSubscriber(t *testing.T) {
	b := &FlowBus{}
	var got []int
	b.Subscribe(func(fl []Flow) { got = append(got, 1) })
	b.Subscribe(func(fl []Flow) { panic("broken subscriber") })
	b.Subscribe(func(fl []Flow) { got = append(got, len(fl)) })
	b.Publish([]Flow{{SrcIP: "10.0.0.1"}, {SrcIP: "10.0.0.2"}})
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("subscribers after a panicking one must still run: %v", got)
	}
}
