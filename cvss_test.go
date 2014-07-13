package cvss

import "testing"

func TestFromVector(t *testing.T) {
	var _, err = NewFromVector("AV:N/AC:H/I:N/A:N")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
}

func TestFromVectorFails(t *testing.T) {
	var _, err = NewFromVector("This is not valid")
	if err == nil {
		t.Errorf("New from vector should have failed but did not")
	}
}

func TestCve_2002_0392_HighEnv(t *testing.T) {
	var c, err = NewFromVector("AV:N/AC:L/Au:N/C:N/I:N/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.Functional)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.High)
	c.AddVector(TD.High)
	c.AddVector(CR.High)
	c.AddVector(IR.High)
	c.AddVector(AR.High)

	s := c.Score()
	expected := Score{7.8, 6.4, 9.2}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v", expected, s)
	}
}

func TestCve_2002_0392_LowEnv(t *testing.T) {
	var c, err = NewFromVector("AV:N/AC:L/Au:N/C:N/I:N/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.Functional)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.None)
	c.AddVector(TD.None)
	c.AddVector(CR.Medium)
	c.AddVector(IR.Medium)
	c.AddVector(AR.High)

	s := c.Score()
	expected := Score{7.8, 6.4, 0.0}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v\n%s", expected, s, c.collateralDamagePotential())
	}
}

func TestCve_2003_0818_HighEnv(t *testing.T) {
	var c, err = NewFromVector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.Functional)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.High)
	c.AddVector(TD.High)
	c.AddVector(CR.Medium)
	c.AddVector(IR.Medium)
	c.AddVector(AR.Low)

	s := c.Score()
	expected := Score{10.0, 8.3, 9.0}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v", expected, s)
	}
}

func TestCve_2003_0818_LowEnv(t *testing.T) {
	var c, err = NewFromVector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.Functional)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.None)
	c.AddVector(TD.None)
	c.AddVector(CR.Medium)
	c.AddVector(IR.Medium)
	c.AddVector(AR.Low)

	s := c.Score()
	expected := Score{10.0, 8.3, 0.0}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v", expected, s)
	}
}

func TestCve_2003_0062_HighEnv(t *testing.T) {
	var c, err = NewFromVector("AV:L/AC:H/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.ProofOfConcept)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.High)
	c.AddVector(TD.High)
	c.AddVector(CR.Medium)
	c.AddVector(IR.Medium)
	c.AddVector(AR.Medium)

	s := c.Score()
	expected := Score{6.2, 4.9, 7.5}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v", expected, s)
	}
}

func TestCve_2003_0062_LowEnv(t *testing.T) {
	var c, err = NewFromVector("AV:L/AC:H/Au:N/C:C/I:C/A:C")
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	// Temp
	c.AddVector(E.ProofOfConcept)
	c.AddVector(RL.OfficialFix)
	c.AddVector(RC.Confirmed)
	// Env
	c.AddVector(CDP.None)
	c.AddVector(TD.None)
	c.AddVector(CR.Medium)
	c.AddVector(IR.Medium)
	c.AddVector(AR.Medium)

	s := c.Score()
	expected := Score{6.2, 4.9, 0.0}
	if s != expected {
		t.Errorf("Score differ, expected %v got %v", expected, s)
	}
}

func TestToVector(t *testing.T) {
	originalVec := "AV:L/AC:H/Au:N/C:C/I:C/A:C"
	// We always sort the output to be predictable.
	expected := "A:C/AC:H/AV:L/Au:N/C:C/I:C"
	var c, err = NewFromVector(originalVec)
	if err != nil {
		t.Errorf("New from vector failed: %v", err)
	}
	v := c.ToVector()
	if v != expected {
		t.Errorf("ToVector result differs, expected %v got %v", expected, v)
	}
}

func TestAddRemovesAlreadyPresentMetrics(t *testing.T) {
	c := NewCvss()
	c.AddVector(AV.Network)
	if !c.HasVector(AV.Network) {
		t.Errorf("Expected to have AV.Network but did not")
	}
	c.AddVector(AV.Local)
	if c.HasVector(AV.Network) {
		t.Errorf("Expected to not have AV.Network anymore but did")
	}
	if !c.HasVector(AV.Local) {
		t.Errorf("Expected to have AV.Local but did not")
	}
}

func TestToString(t *testing.T) {
	s := NewCvss().String()
	if len(s) == 0 {
		t.Errorf("Should have produced a string of lenght >0")
	}
}
