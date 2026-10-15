package tc

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestClassLifecycle(t *testing.T) {
	var commands []string
	run := func(args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	}
	m, err := openClasses([]string{"n3", "n6"}, run)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !slices.Contains(commands, "filter add dev n3 parent e001: protocol all matchall classid e001:1") {
		t.Fatal("unmarked traffic has no default class", commands)
	}
	id, created, err := m.Prepare(7, "n6")
	if err != nil || !created || id != 0xe0010002 {
		t.Fatal(id, created, err)
	}
	m.Commit(7)
	again, created, err := m.Prepare(7, "n6")
	if err != nil || created || again != id {
		t.Fatal(again, created, err)
	}
	other, created, err := m.Prepare(8, "n6")
	if err != nil || !created || other != 0xe0010003 {
		t.Fatal(other, created, err)
	}
	if err := m.Rollback(8, true); err != nil {
		t.Fatal(err)
	}
	moved, created, err := m.Prepare(7, "n3")
	if err != nil || !created || moved != 0xe0010002 {
		t.Fatal(moved, created, err)
	}
	m.Commit(7)
	if err := m.Delete(7); err != nil {
		t.Fatal(err)
	}
	if len(m.active) != 0 || m.used["n3"][2] || m.used["n6"][2] {
		t.Fatal("class resources were not released")
	}
	if !slices.Contains(commands, "class del dev n6 classid e001:2") ||
		!slices.Contains(commands, "class del dev n3 classid e001:2") {
		t.Fatal("old or current class not removed", commands)
	}
}

func TestClassSetupFailureRemovesOnlyCreatedRoots(t *testing.T) {
	var commands []string
	run := func(args ...string) error {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if command == "qdisc add dev n6 root handle e001: drr" {
			return errors.New("root belongs to another owner")
		}
		return nil
	}
	_, err := openClasses([]string{"n3", "n6"}, run)
	if err == nil {
		t.Fatal("expected root setup failure")
	}
	var deleted []string
	for _, command := range commands {
		if strings.HasPrefix(command, "qdisc del") {
			deleted = append(deleted, command)
		}
	}
	if !reflect.DeepEqual(deleted, []string{"qdisc del dev n3 root handle e001:"}) {
		t.Fatal("cleanup touched an unowned root", deleted)
	}
}
