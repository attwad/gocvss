// Package cvss provides cvss computation methods.
// It follows the specifications at http://www.first.org/cvss/cvss-guide
package cvss

import (
	"fmt"
	"sort"
	"strings"
)

// Score is a struct of CVSS scores computed from various vectors.
type Score struct {
	Base          float64
	Temporal      float64
	Environmental float64
}

// A metric is a single vector in CVSS, see the full list declared in the const section.
type Metric int

// A CVSS is simply just a vector of metrics.
type CVSS []Metric

// Parse creates a new Cvss from a short form string vector.
// Example: "AV:N/AC:H/I:N/A:N"
func Parse(s string) (cvss CVSS, err error) {
	for _, name := range strings.Split(s, "/") {
		m, ok := nameToMetric[name]
		if !ok {
			return nil, fmt.Errorf("cvss: unrecognized metric %q", name)
		}
		cvss = append(cvss, m)
	}
	return cvss, nil
}

// ToStringVector returns the CVSS to its short string vector form.
// Example: "AV:N/AC:H/I:N/A:N"
func (c CVSS) ToStringVector() string {
	s := make([]string, len(c))
	for i, metric := range c {
		s[i] = names[metric]
	}
	sort.Strings(s)
	return strings.Join(s, "/")
}

// String provides a human readable version of the metrics and scores associated with the model.
func (c CVSS) String() string {
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

const (
	noMetric Metric = iota
	AccessVectorLocal
	AccessVectorAdjacent
	AccessVectorNetwork

	AccessComplexityHigh
	AccessComplexityMedium
	AccessComplexityLow

	AuthenticationMultiple
	AuthenticationSingle
	AuthenticationNone

	ConfidentialityNone
	ConfidentialityPartial
	ConfidentialityComplete

	IntegrityNone
	IntegrityPartial
	IntegrityComplete

	AvailabilityNone
	AvailabilityPartial
	AvailabilityComplete

	ExploitabilityUnproven
	ExploitabilityProofOfConcept
	ExploitabilityFunctional
	ExploitabilityHigh
	ExploitabilityNotDefined

	RemediationLevelOfficialFix
	RemediationLevelTemporaryFix
	RemediationLevelWorkaround
	RemediationLevelUnavailable
	RemediationLevelNotDefined

	ReportConfidenceUnconfirmed
	ReportConfidenceUncorroborated
	ReportConfidenceConfirmed
	ReportConfidenceNotDefined

	CollateralDamagePotentialNone
	CollateralDamagePotentialLow
	CollateralDamagePotentialLowMedium
	CollateralDamagePotentialMediumHigh
	CollateralDamagePotentialHigh
	CollateralDamagePotentialNotDefined

	TargetDistributionNone
	TargetDistributionLow
	TargetDistributionMedium
	TargetDistributionHigh
	TargetDistributionNotDefined

	ConfidentialityRequirementLow
	ConfidentialityRequirementMedium
	ConfidentialityRequirementHigh
	ConfidentialityRequirementNotDefined

	IntegrityRequirementLow
	IntegrityRequirementMedium
	IntegrityRequirementHigh
	IntegrityRequirementNotDefined

	AvailabilityRequirementLow
	AvailabilityRequirementMedium
	AvailabilityRequirementHigh
	AvailabilityRequirementNotDefined
)

var names = [...]string{
	AccessVectorLocal:    "AV:L",
	AccessVectorAdjacent: "AV:A",
	AccessVectorNetwork:  "AV:N",

	AccessComplexityHigh:   "AC:H",
	AccessComplexityMedium: "AC:M",
	AccessComplexityLow:    "AC:L",

	AuthenticationMultiple: "Au:M",
	AuthenticationSingle:   "Au:S",
	AuthenticationNone:     "Au:N",

	ConfidentialityNone:     "C:N",
	ConfidentialityPartial:  "C:P",
	ConfidentialityComplete: "C:C",

	IntegrityNone:     "I:N",
	IntegrityPartial:  "I:P",
	IntegrityComplete: "I:C",

	AvailabilityNone:     "A:N",
	AvailabilityPartial:  "A:P",
	AvailabilityComplete: "A:C",

	ExploitabilityUnproven:       "E:P",
	ExploitabilityProofOfConcept: "E:POC",
	ExploitabilityFunctional:     "E:F",
	ExploitabilityHigh:           "E:H",
	ExploitabilityNotDefined:     "E:ND",

	RemediationLevelOfficialFix:  "RL:OF",
	RemediationLevelTemporaryFix: "RL:TF",
	RemediationLevelWorkaround:   "RL:W",
	RemediationLevelUnavailable:  "RL:U",
	RemediationLevelNotDefined:   "RL:ND",

	ReportConfidenceUnconfirmed:    "RC:U",
	ReportConfidenceUncorroborated: "RC:U",
	ReportConfidenceConfirmed:      "RC:C",
	ReportConfidenceNotDefined:     "RC:ND",

	CollateralDamagePotentialNone:       "CDP:N",
	CollateralDamagePotentialLow:        "CDP:L",
	CollateralDamagePotentialLowMedium:  "CDP:LM",
	CollateralDamagePotentialMediumHigh: "CDP:MH",
	CollateralDamagePotentialHigh:       "CDP:H",
	CollateralDamagePotentialNotDefined: "CDP:ND",

	TargetDistributionNone:       "TD:N",
	TargetDistributionLow:        "TD:L",
	TargetDistributionMedium:     "TD:M",
	TargetDistributionHigh:       "TD:H",
	TargetDistributionNotDefined: "TD:ND",

	ConfidentialityRequirementLow:        "CR:L",
	ConfidentialityRequirementMedium:     "CR:M",
	ConfidentialityRequirementHigh:       "CR:H",
	ConfidentialityRequirementNotDefined: "CR:ND",

	IntegrityRequirementLow:        "IR:L",
	IntegrityRequirementMedium:     "IR:M",
	IntegrityRequirementHigh:       "IR:H",
	IntegrityRequirementNotDefined: "IR:ND",

	AvailabilityRequirementLow:        "AR:L",
	AvailabilityRequirementMedium:     "AR:M",
	AvailabilityRequirementHigh:       "AR:H",
	AvailabilityRequirementNotDefined: "AR:ND",
}

// Create the reverse map of the names to be used when parsing a string
// representing a CVSS in short vector format.
var nameToMetric = func() map[string]Metric {
	ret := map[string]Metric{}
	for m, name := range names {
		ret[name] = Metric(m)
	}
	return ret
}()

var scores = [...]float64{
	AccessVectorLocal:    0.375,
	AccessVectorAdjacent: 0.646,
	AccessVectorNetwork:  1,

	AccessComplexityHigh:   0.35,
	AccessComplexityMedium: 0.61,
	AccessComplexityLow:    0.71,

	AuthenticationMultiple: 0.45,
	AuthenticationSingle:   0.56,
	AuthenticationNone:     0.704,

	ConfidentialityNone:     0,
	ConfidentialityPartial:  0.275,
	ConfidentialityComplete: 0.66,

	IntegrityNone:     0,
	IntegrityPartial:  0.275,
	IntegrityComplete: 0.66,

	AvailabilityNone:     0,
	AvailabilityPartial:  0.275,
	AvailabilityComplete: 0.66,

	ExploitabilityUnproven:       0.85,
	ExploitabilityProofOfConcept: 0.9,
	ExploitabilityFunctional:     0.95,
	ExploitabilityHigh:           1,
	ExploitabilityNotDefined:     1,

	RemediationLevelOfficialFix:  0.87,
	RemediationLevelTemporaryFix: 0.9,
	RemediationLevelWorkaround:   0.95,
	RemediationLevelUnavailable:  1,
	RemediationLevelNotDefined:   1,

	ReportConfidenceUnconfirmed:    0.9,
	ReportConfidenceUncorroborated: 0.95,
	ReportConfidenceConfirmed:      1,
	ReportConfidenceNotDefined:     1,

	CollateralDamagePotentialNone:       0,
	CollateralDamagePotentialLow:        1,
	CollateralDamagePotentialLowMedium:  0.3,
	CollateralDamagePotentialMediumHigh: 0.4,
	CollateralDamagePotentialHigh:       0.5,
	CollateralDamagePotentialNotDefined: 0,

	TargetDistributionNone:       0,
	TargetDistributionLow:        0.25,
	TargetDistributionMedium:     0.75,
	TargetDistributionHigh:       1,
	TargetDistributionNotDefined: 0,

	ConfidentialityRequirementLow:        0.5,
	ConfidentialityRequirementMedium:     1,
	ConfidentialityRequirementHigh:       1.51,
	ConfidentialityRequirementNotDefined: 1,

	IntegrityRequirementLow:        0.5,
	IntegrityRequirementMedium:     1,
	IntegrityRequirementHigh:       1.51,
	IntegrityRequirementNotDefined: 1,

	AvailabilityRequirementLow:        0.5,
	AvailabilityRequirementMedium:     1,
	AvailabilityRequirementHigh:       1.51,
	AvailabilityRequirementNotDefined: 1,
}

type group int

const (
	noGroup group = iota
	accessVector
	accessComplexity
	authentication
	confidentiality
	integrity
	availability
	exploitability
	remediationLevel
	reportConfidence
	collateralDamagePotential
	targetDistribution
	confidentialityRequirement
	integrityRequirement
	availabilityRequirement
)

var groups = [...]group{
	AccessVectorLocal:    accessVector,
	AccessVectorAdjacent: accessVector,
	AccessVectorNetwork:  accessVector,

	AccessComplexityHigh:   accessComplexity,
	AccessComplexityMedium: accessComplexity,
	AccessComplexityLow:    accessComplexity,

	AuthenticationMultiple: authentication,
	AuthenticationSingle:   authentication,
	AuthenticationNone:     authentication,

	ConfidentialityNone:     confidentiality,
	ConfidentialityPartial:  confidentiality,
	ConfidentialityComplete: confidentiality,

	IntegrityNone:     integrity,
	IntegrityPartial:  integrity,
	IntegrityComplete: integrity,

	AvailabilityNone:     availability,
	AvailabilityPartial:  availability,
	AvailabilityComplete: availability,

	ExploitabilityUnproven:       exploitability,
	ExploitabilityProofOfConcept: exploitability,
	ExploitabilityFunctional:     exploitability,
	ExploitabilityHigh:           exploitability,
	ExploitabilityNotDefined:     exploitability,

	RemediationLevelOfficialFix:  remediationLevel,
	RemediationLevelTemporaryFix: remediationLevel,
	RemediationLevelWorkaround:   remediationLevel,
	RemediationLevelUnavailable:  remediationLevel,
	RemediationLevelNotDefined:   remediationLevel,

	ReportConfidenceUnconfirmed:    reportConfidence,
	ReportConfidenceUncorroborated: reportConfidence,
	ReportConfidenceConfirmed:      reportConfidence,
	ReportConfidenceNotDefined:     reportConfidence,

	CollateralDamagePotentialNone:       collateralDamagePotential,
	CollateralDamagePotentialLow:        collateralDamagePotential,
	CollateralDamagePotentialLowMedium:  collateralDamagePotential,
	CollateralDamagePotentialMediumHigh: collateralDamagePotential,
	CollateralDamagePotentialHigh:       collateralDamagePotential,
	CollateralDamagePotentialNotDefined: collateralDamagePotential,

	TargetDistributionNone:       targetDistribution,
	TargetDistributionLow:        targetDistribution,
	TargetDistributionMedium:     targetDistribution,
	TargetDistributionHigh:       targetDistribution,
	TargetDistributionNotDefined: targetDistribution,

	ConfidentialityRequirementLow:        confidentiality,
	ConfidentialityRequirementMedium:     confidentiality,
	ConfidentialityRequirementHigh:       confidentiality,
	ConfidentialityRequirementNotDefined: confidentiality,

	IntegrityRequirementLow:        integrityRequirement,
	IntegrityRequirementMedium:     integrityRequirement,
	IntegrityRequirementHigh:       integrityRequirement,
	IntegrityRequirementNotDefined: integrityRequirement,

	AvailabilityRequirementLow:        availabilityRequirement,
	AvailabilityRequirementMedium:     availabilityRequirement,
	AvailabilityRequirementHigh:       availabilityRequirement,
	AvailabilityRequirementNotDefined: availabilityRequirement,
}
