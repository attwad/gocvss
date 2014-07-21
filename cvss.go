// This package provides cvss computation methods.
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
	AccessVector_Local
	AccessVector_Adjacent
	AccessVector_Network

	AccessComplexity_High
	AccessComplexity_Medium
	AccessComplexity_Low

	Authentication_Multiple
	Authentication_Single
	Authentication_None

	Confidentiality_None
	Confidentiality_Partial
	Confidentiality_Complete

	Integrity_None
	Integrity_Partial
	Integrity_Complete

	Availability_None
	Availability_Partial
	Availability_Complete

	Exploitability_Unproven
	Exploitability_ProofOfConcept
	Exploitability_Functional
	Exploitability_High
	Exploitability_NotDefined

	RemediationLevel_OfficialFix
	RemediationLevel_TemporaryFix
	RemediationLevel_Workaround
	RemediationLevel_Unavailable
	RemediationLevel_NotDefined

	ReportConfidence_Unconfirmed
	ReportConfidence_Uncorroborated
	ReportConfidence_Confirmed
	ReportConfidence_NotDefined

	CollateralDamagePotential_None
	CollateralDamagePotential_Low
	CollateralDamagePotential_LowMedium
	CollateralDamagePotential_MediumHigh
	CollateralDamagePotential_High
	CollateralDamagePotential_NotDefined

	TargetDistribution_None
	TargetDistribution_Low
	TargetDistribution_Medium
	TargetDistribution_High
	TargetDistribution_NotDefined

	ConfidentialityRequirement_Low
	ConfidentialityRequirement_Medium
	ConfidentialityRequirement_High
	ConfidentialityRequirement_NotDefined

	IntegrityRequirement_Low
	IntegrityRequirement_Medium
	IntegrityRequirement_High
	IntegrityRequirement_NotDefined

	AvailabilityRequirement_Low
	AvailabilityRequirement_Medium
	AvailabilityRequirement_High
	AvailabilityRequirement_NotDefined
)

var names = [...]string{
	AccessVector_Local:    "AV:L",
	AccessVector_Adjacent: "AV:A",
	AccessVector_Network:  "AV:N",

	AccessComplexity_High:   "AC:H",
	AccessComplexity_Medium: "AC:M",
	AccessComplexity_Low:    "AC:L",

	Authentication_Multiple: "Au:M",
	Authentication_Single:   "Au:S",
	Authentication_None:     "Au:N",

	Confidentiality_None:     "C:N",
	Confidentiality_Partial:  "C:P",
	Confidentiality_Complete: "C:C",

	Integrity_None:     "I:N",
	Integrity_Partial:  "I:P",
	Integrity_Complete: "I:C",

	Availability_None:     "A:N",
	Availability_Partial:  "A:P",
	Availability_Complete: "A:C",

	Exploitability_Unproven:       "E:P",
	Exploitability_ProofOfConcept: "E:POC",
	Exploitability_Functional:     "E:F",
	Exploitability_High:           "E:H",
	Exploitability_NotDefined:     "E:ND",

	RemediationLevel_OfficialFix:  "RL:OF",
	RemediationLevel_TemporaryFix: "RL:TF",
	RemediationLevel_Workaround:   "RL:W",
	RemediationLevel_Unavailable:  "RL:U",
	RemediationLevel_NotDefined:   "RL:ND",

	ReportConfidence_Unconfirmed:    "RC:U",
	ReportConfidence_Uncorroborated: "RC:U",
	ReportConfidence_Confirmed:      "RC:C",
	ReportConfidence_NotDefined:     "RC:ND",

	CollateralDamagePotential_None:       "CDP:N",
	CollateralDamagePotential_Low:        "CDP:L",
	CollateralDamagePotential_LowMedium:  "CDP:LM",
	CollateralDamagePotential_MediumHigh: "CDP:MH",
	CollateralDamagePotential_High:       "CDP:H",
	CollateralDamagePotential_NotDefined: "CDP:ND",

	TargetDistribution_None:       "TD:N",
	TargetDistribution_Low:        "TD:L",
	TargetDistribution_Medium:     "TD:M",
	TargetDistribution_High:       "TD:H",
	TargetDistribution_NotDefined: "TD:ND",

	ConfidentialityRequirement_Low:        "CR:L",
	ConfidentialityRequirement_Medium:     "CR:M",
	ConfidentialityRequirement_High:       "CR:H",
	ConfidentialityRequirement_NotDefined: "CR:ND",

	IntegrityRequirement_Low:        "IR:L",
	IntegrityRequirement_Medium:     "IR:M",
	IntegrityRequirement_High:       "IR:H",
	IntegrityRequirement_NotDefined: "IR:ND",

	AvailabilityRequirement_Low:        "AR:L",
	AvailabilityRequirement_Medium:     "AR:M",
	AvailabilityRequirement_High:       "AR:H",
	AvailabilityRequirement_NotDefined: "AR:ND",
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
	AccessVector_Local:    0.375,
	AccessVector_Adjacent: 0.646,
	AccessVector_Network:  1,

	AccessComplexity_High:   0.35,
	AccessComplexity_Medium: 0.61,
	AccessComplexity_Low:    0.71,

	Authentication_Multiple: 0.45,
	Authentication_Single:   0.56,
	Authentication_None:     0.704,

	Confidentiality_None:     0,
	Confidentiality_Partial:  0.275,
	Confidentiality_Complete: 0.66,

	Integrity_None:     0,
	Integrity_Partial:  0.275,
	Integrity_Complete: 0.66,

	Availability_None:     0,
	Availability_Partial:  0.275,
	Availability_Complete: 0.66,

	Exploitability_Unproven:       0.85,
	Exploitability_ProofOfConcept: 0.9,
	Exploitability_Functional:     0.95,
	Exploitability_High:           1,
	Exploitability_NotDefined:     1,

	RemediationLevel_OfficialFix:  0.87,
	RemediationLevel_TemporaryFix: 0.9,
	RemediationLevel_Workaround:   0.95,
	RemediationLevel_Unavailable:  1,
	RemediationLevel_NotDefined:   1,

	ReportConfidence_Unconfirmed:    0.9,
	ReportConfidence_Uncorroborated: 0.95,
	ReportConfidence_Confirmed:      1,
	ReportConfidence_NotDefined:     1,

	CollateralDamagePotential_None:       0,
	CollateralDamagePotential_Low:        1,
	CollateralDamagePotential_LowMedium:  0.3,
	CollateralDamagePotential_MediumHigh: 0.4,
	CollateralDamagePotential_High:       0.5,
	CollateralDamagePotential_NotDefined: 0,

	TargetDistribution_None:       0,
	TargetDistribution_Low:        0.25,
	TargetDistribution_Medium:     0.75,
	TargetDistribution_High:       1,
	TargetDistribution_NotDefined: 0,

	ConfidentialityRequirement_Low:        0.5,
	ConfidentialityRequirement_Medium:     1,
	ConfidentialityRequirement_High:       1.51,
	ConfidentialityRequirement_NotDefined: 1,

	IntegrityRequirement_Low:        0.5,
	IntegrityRequirement_Medium:     1,
	IntegrityRequirement_High:       1.51,
	IntegrityRequirement_NotDefined: 1,

	AvailabilityRequirement_Low:        0.5,
	AvailabilityRequirement_Medium:     1,
	AvailabilityRequirement_High:       1.51,
	AvailabilityRequirement_NotDefined: 1,
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
	AccessVector_Local:    accessVector,
	AccessVector_Adjacent: accessVector,
	AccessVector_Network:  accessVector,

	AccessComplexity_High:   accessComplexity,
	AccessComplexity_Medium: accessComplexity,
	AccessComplexity_Low:    accessComplexity,

	Authentication_Multiple: authentication,
	Authentication_Single:   authentication,
	Authentication_None:     authentication,

	Confidentiality_None:     confidentiality,
	Confidentiality_Partial:  confidentiality,
	Confidentiality_Complete: confidentiality,

	Integrity_None:     integrity,
	Integrity_Partial:  integrity,
	Integrity_Complete: integrity,

	Availability_None:     availability,
	Availability_Partial:  availability,
	Availability_Complete: availability,

	Exploitability_Unproven:       exploitability,
	Exploitability_ProofOfConcept: exploitability,
	Exploitability_Functional:     exploitability,
	Exploitability_High:           exploitability,
	Exploitability_NotDefined:     exploitability,

	RemediationLevel_OfficialFix:  remediationLevel,
	RemediationLevel_TemporaryFix: remediationLevel,
	RemediationLevel_Workaround:   remediationLevel,
	RemediationLevel_Unavailable:  remediationLevel,
	RemediationLevel_NotDefined:   remediationLevel,

	ReportConfidence_Unconfirmed:    reportConfidence,
	ReportConfidence_Uncorroborated: reportConfidence,
	ReportConfidence_Confirmed:      reportConfidence,
	ReportConfidence_NotDefined:     reportConfidence,

	CollateralDamagePotential_None:       collateralDamagePotential,
	CollateralDamagePotential_Low:        collateralDamagePotential,
	CollateralDamagePotential_LowMedium:  collateralDamagePotential,
	CollateralDamagePotential_MediumHigh: collateralDamagePotential,
	CollateralDamagePotential_High:       collateralDamagePotential,
	CollateralDamagePotential_NotDefined: collateralDamagePotential,

	TargetDistribution_None:       targetDistribution,
	TargetDistribution_Low:        targetDistribution,
	TargetDistribution_Medium:     targetDistribution,
	TargetDistribution_High:       targetDistribution,
	TargetDistribution_NotDefined: targetDistribution,

	ConfidentialityRequirement_Low:        confidentiality,
	ConfidentialityRequirement_Medium:     confidentiality,
	ConfidentialityRequirement_High:       confidentiality,
	ConfidentialityRequirement_NotDefined: confidentiality,

	IntegrityRequirement_Low:        integrityRequirement,
	IntegrityRequirement_Medium:     integrityRequirement,
	IntegrityRequirement_High:       integrityRequirement,
	IntegrityRequirement_NotDefined: integrityRequirement,

	AvailabilityRequirement_Low:        availabilityRequirement,
	AvailabilityRequirement_Medium:     availabilityRequirement,
	AvailabilityRequirement_High:       availabilityRequirement,
	AvailabilityRequirement_NotDefined: availabilityRequirement,
}
