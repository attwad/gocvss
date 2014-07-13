// This package provides cvss computation methods.
// Follows the specifications at http://www.first.org/cvss/cvss-guide
package cvss

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// A struct of CVSS scores computed from various vectors.
type Score struct {
	Base          float64
	Temporal      float64
	Environmental float64
}

// A single CVSS metric vector.
type Vector struct {
	// A unique name describing this vector.
	Name string
	// Short name used in the short vector form.
	ShortName string
	// The short name prefixed with its metric, as found in the serialized form.
	fullShortName string
	// Internaly used score to compute overall scores.
	score float64
}

type metric interface {
	Vectors() []Vector
}

func vectorForName(m metric, name string) *Vector {
	for _, vec := range m.Vectors() {
		if vec.ShortName == name {
			return &vec
		}
	}
	return nil
}

// Creates a new Cvss struct from a short form string vector.
// Example: "AV:N/AC:H/I:N/A:N"
func NewFromVector(s string) (*Cvss, error) {
	c := NewCvss()
	if len(s) == 0 {
		return c, nil
	}
	for _, metric := range strings.Split(s, "/") {
		split := strings.Split(metric, ":")
		if len(split) != 2 {
			return nil, errors.New(fmt.Sprintf("Vector malformed: %v", split))
		}
		metricShortName, vectorValue := split[0], split[1]
		m := metricShortNameToInstance[metricShortName]
		vec := vectorForName(m, vectorValue)
		if vec == nil {
			return nil, errors.New(fmt.Sprintf("Could not find vector for value %v", vectorValue))
		}
		c.addVectorOfMetric(*vec, m)
	}
	return c, nil
}

// Need to find a better name... model?
type Cvss struct {
	vectors map[Vector]bool
}

// Creates a ready to use Cvss instance.
func NewCvss() *Cvss {
	c := new(Cvss)
	c.vectors = make(map[Vector]bool)
	return c
}

// Adds a vector to this Cvss model. Will remove any existing value for the same metric if present.
func (c *Cvss) AddVector(newVec Vector) {
	// Until I find a way to get the metric of a vector nicely, we are stuck with 2 for loops, that's not nice at all...
	for _, m := range allMetrics {
		for _, v := range m.Vectors() {
			if v == newVec {
				c.addVectorOfMetric(newVec, m)
				return
			}
		}
	}
}

func (c *Cvss) addVectorOfMetric(newVec Vector, m metric) {
	// Remove the existing values for this metric if any.
	for _, vec := range m.Vectors() {
		c.RemoveVector(vec)
	}
	// Then add our new vector.
	c.vectors[newVec] = true
}

// Removes a vector from this model, no-op if it was not present.
func (c *Cvss) RemoveVector(v Vector) {
	delete(c.vectors, v)
}

// Returns true of the vector was set in this Cvss model.
func (c *Cvss) HasVector(v Vector) bool {
	if _, ok := c.vectors[v]; ok {
		return true
	}
	return false
}

// Provides a human readable version of the metrics and scores associated with the model.
func (c *Cvss) String() string {
	return fmt.Sprintf(
		"base score                     %f\n"+
			"  access vector                %f\n"+
			"  access complexity            %f\n"+
			"  authentication               %f\n"+
			"  confidentiality impact       %f\n"+
			"  integrity impact             %f\n"+
			"  availability impact          %f\n"+
			"\n"+
			"temporal score                 %f\n"+
			"  exploitability               %f\n"+
			"  remediation level            %f\n"+
			"  report confidence            %f\n"+
			"\n"+
			"environmental score            %f\n"+
			"  collateral damage potential  %f\n"+
			"  target distribution          %f\n"+
			"  confidentiality requirement  %f\n"+
			"  integrity requirement        %f\n"+
			"  availability requirement     %f\n",
		c.baseScore(),
		c.accessVectorScore(),
		c.accessComplexityScore(),
		c.authenticationScore(),
		c.confidentialityImpact(),
		c.integrityImpact(),
		c.availabilityImpact(),

		c.temporalScore(),
		c.temporalExploitability(),
		c.remediationLevel(),
		c.reportConfidence(),

		c.environmentalScore(),
		c.collateralDamagePotential(),
		c.targetDistribution(),
		c.confidentialityRequirement(),
		c.integrityRequirement(),
		c.availabilityRequirement(),
	)
}

// Sort interface called by ToVector()...
type byFullShortName []string

func (b byFullShortName) Len() int {
	return len(b)
}

func (b byFullShortName) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b byFullShortName) Less(i, j int) bool {
	return b[i] < b[j]
}

func (c *Cvss) ToVector() string {
	// We have 16 vectors max in our map.
	s := make([]string, 0)
	for k, _ := range c.vectors {
		s = append(s, k.fullShortName)
	}
	sort.Sort(byFullShortName(s))
	return strings.Join(s, "/")
}

var (
	AV  = newAccessVector()
	AC  = newAccessComplexity()
	Au  = newAuthentication()
	C   = newConfidentiality()
	I   = newIntegrity()
	A   = newAvailability()
	E   = newExploitability()
	RL  = newRemediationLevel()
	RC  = newReportConfidence()
	CDP = newCollateralDamagePotential()
	TD  = newTargetDistribution()
	CR  = newConfidentialityRequirement()
	IR  = newIntegrityRequirement()
	AR  = newAvailabilityRequirement()

	allMetrics = []metric{AV, AC, Au, C, I, A, E, RL, RC, CDP, TD, CR, IR, AR}

	metricShortNameToInstance = map[string]metric{
		"AV":  AV,
		"AC":  AC,
		"Au":  Au,
		"C":   C,
		"I":   I,
		"A":   A,
		"E":   E,
		"RL":  RL,
		"RC":  RC,
		"CDP": CDP,
		"TD":  TD,
		"CR":  CR,
		"IR":  IR,
		"AR":  AR,
	}
)
