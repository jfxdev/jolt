package jobs

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func TestCopyOperationsRefuseSecuredJobWithoutFilter(t *testing.T) {
	service, _, mountID := testService(t)
	for name, job := range map[string]entities.Job{
		"bound":     {ID: "job", MountID: mountID, SignedAuthBound: true},
		"requires":  {ID: "job", MountID: mountID, RequiresSignedAuth: true},
		"destroyer": {ID: "job", MountID: mountID, DestructivePlanID: "plan"},
	} {
		if _, err := service.copyOperations(context.Background(), job); !errors.Is(err, ErrAuthorizationRequired) {
			t.Fatalf("%s job ran without a filter: %v", name, err)
		}
		job.Type, job.SourcePath, job.Destination = "copy_local", "source", "destination"
		if _, err := service.executeCopy(context.Background(), job); !errors.Is(err, ErrAuthorizationRequired) {
			t.Fatalf("%s copy executed without a filter: %v", name, err)
		}
	}
	ops, err := service.copyOperations(context.Background(), entities.Job{ID: "job", MountID: mountID})
	if err != nil || ops.filter != nil {
		t.Fatalf("ordinary job was not unfiltered: %+v %v", ops, err)
	}
	ops, err = service.copyOperations(withAccessFilter(context.Background(), copyPlanFilter(t)), entities.Job{ID: "job", MountID: mountID, SignedAuthBound: true})
	if err != nil || ops.filter == nil {
		t.Fatalf("secured job lost its filter: %+v %v", ops, err)
	}
}

func TestCopyWarningReportsOnlyCounts(t *testing.T) {
	if err := copyWarning(0, 0); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		failed, omitted int
		want            string
	}{
		{2, 0, "2 item(s) could not be copied"},
		{0, 3, "3 source entries were not accessible"},
		{1, 4, "1 item(s) could not be copied; 4 source entries were not accessible"},
	} {
		err := copyWarning(test.failed, test.omitted)
		if !errors.Is(err, ErrWarnings) || !strings.HasSuffix(err.Error(), test.want) {
			t.Fatalf("copyWarning(%d,%d)=%v", test.failed, test.omitted, err)
		}
	}
}
