package cvss

// This metric reflects how the vulnerability is exploited.
// The more remote an attacker can be to attack a host, the greater the vulnerability score.
type AccessVector struct {
	Local    Vector
	Adjacent Vector
	Network  Vector

	vectors []Vector
}

func (m *AccessVector) Vectors() []Vector {
	return m.vectors
}

func newAccessVector() *AccessVector {
	v := new(AccessVector)
	v.Local = Vector{"Access vector: local", "L", "AV:L", 0.395}
	v.Adjacent = Vector{"Access vector: adjacent", "A", "AV:A", 0.646}
	v.Network = Vector{"Access vector: network", "N", "AV:N", 1.0}
	v.vectors = []Vector{v.Local, v.Adjacent, v.Network}
	return v
}

type AccessComplexity struct {
	High   Vector
	Medium Vector
	Low    Vector

	vectors []Vector
}

func (m *AccessComplexity) Vectors() []Vector {
	return m.vectors
}

func newAccessComplexity() *AccessComplexity {
	v := new(AccessComplexity)
	v.High = Vector{"Complexity: high", "H", "AC:H", 0.35}
	v.Medium = Vector{"Complexity: medium", "M", "AC:M", 0.61}
	v.Low = Vector{"Complexity: low", "L", "AC:L", 0.71}
	v.vectors = []Vector{v.High, v.Medium, v.Low}
	return v
}

type Authentication struct {
	Multiple Vector
	Single   Vector
	None     Vector

	vectors []Vector
}

func (m *Authentication) Vectors() []Vector {
	return m.vectors
}

func newAuthentication() *Authentication {
	v := new(Authentication)
	v.Multiple = Vector{"Authentication: multiple", "M", "Au:M", 0.45}
	v.Single = Vector{"Authentication: single", "S", "Au:S", 0.56}
	v.None = Vector{"Authentication: none", "N", "Au:N", 0.704}
	v.vectors = []Vector{v.Multiple, v.Single, v.None}
	return v
}

type Confidentiality struct {
	None     Vector
	Partial  Vector
	Complete Vector

	vectors []Vector
}

func (m *Confidentiality) Vectors() []Vector {
	return m.vectors
}

func newConfidentiality() *Confidentiality {
	v := new(Confidentiality)
	v.None = Vector{"Confidentiality: none", "N", "C:N", 0.0}
	v.Partial = Vector{"Confidentiality: partial", "P", "C:P", 0.275}
	v.Complete = Vector{"Confidentiality complete", "C", "C:C", 0.660}
	v.vectors = []Vector{v.None, v.Partial, v.Complete}
	return v
}

type Integrity struct {
	None     Vector
	Partial  Vector
	Complete Vector

	vectors []Vector
}

func (m *Integrity) Vectors() []Vector {
	return m.vectors
}

func newIntegrity() *Integrity {
	v := new(Integrity)
	v.None = Vector{"Integrity: none", "N", "I:N", 0.0}
	v.Partial = Vector{"Integrity: partial", "P", "I:P", 0.275}
	v.Complete = Vector{"Integrity: complete", "C", "I:C", 0.660}
	v.vectors = []Vector{v.None, v.Partial, v.Complete}
	return v
}

type Availability struct {
	None     Vector
	Partial  Vector
	Complete Vector

	vectors []Vector
}

func (m *Availability) Vectors() []Vector {
	return m.vectors
}

func newAvailability() *Availability {
	v := new(Availability)
	v.None = Vector{"Availability: none", "N", "A:N", 0.0}
	v.Partial = Vector{"Availability: partial", "P", "A:P", 0.275}
	v.Complete = Vector{"Availability: complete", "C", "A:C", 0.660}
	v.vectors = []Vector{v.None, v.Partial, v.Complete}
	return v
}

type Exploitability struct {
	Unproven       Vector
	ProofOfConcept Vector
	Functional     Vector
	High           Vector
	NotDefined     Vector

	vectors []Vector
}

func (m *Exploitability) Vectors() []Vector {
	return m.vectors
}

func newExploitability() *Exploitability {
	v := new(Exploitability)
	v.Unproven = Vector{"Exploitability: unproven", "U", "E:U", 0.85}
	v.ProofOfConcept = Vector{"Exploitability: proof of concept", "POC", "E:POC", 0.9}
	v.Functional = Vector{"Exploitability: functional", "F", "E:F", 0.95}
	v.High = Vector{"Exploitability: high", "H", "E:H", 1.0}
	v.NotDefined = Vector{"Exploitability: not defined", "ND", "E:ND", 1.0}
	v.vectors = []Vector{v.Unproven, v.ProofOfConcept, v.Functional, v.High, v.NotDefined}
	return v
}

type RemediationLevel struct {
	OfficialFix  Vector
	TemporaryFix Vector
	Workaround   Vector
	Unavailable  Vector
	NotDefined   Vector

	vectors []Vector
}

func (m *RemediationLevel) Vectors() []Vector {
	return m.vectors
}

func newRemediationLevel() *RemediationLevel {
	v := new(RemediationLevel)
	v.OfficialFix = Vector{"Remediation level: official fix", "OF", "RL:OF", 0.87}
	v.TemporaryFix = Vector{"Remediation level: temporary fix", "TF", "RL:TF", 0.9}
	v.Workaround = Vector{"Remediation level: workaround", "W", "RL:W", 0.95}
	v.Unavailable = Vector{"Remediation level: unavailable", "U", "RL:U", 1.0}
	v.NotDefined = Vector{"Remediation level: not defined", "ND", "RL:ND", 1.0}
	v.vectors = []Vector{v.OfficialFix, v.TemporaryFix, v.Workaround, v.Unavailable, v.NotDefined}
	return v
}

type ReportConfidence struct {
	Unconfirmed    Vector
	Uncorroborated Vector
	Confirmed      Vector
	NotDefined     Vector

	vectors []Vector
}

func (m *ReportConfidence) Vectors() []Vector {
	return m.vectors
}

func newReportConfidence() *ReportConfidence {
	v := new(ReportConfidence)
	v.Unconfirmed = Vector{"Report confidence: unconfirmed", "UC", "RC:UC", 0.9}
	v.Uncorroborated = Vector{"Report confidence: uncorroborated", "UR", "RC:UR", 0.95}
	v.Confirmed = Vector{"Report confidence: confirmed", "C", "RC:C", 1.0}
	v.NotDefined = Vector{"Report confidence: not defined", "ND", "RC:ND", 1.0}
	v.vectors = []Vector{v.Unconfirmed, v.Uncorroborated, v.Confirmed, v.NotDefined}
	return v
}

type CollateralDamagePotential struct {
	None       Vector
	Low        Vector
	LowMedium  Vector
	MediumHigh Vector
	High       Vector
	NotDefined Vector

	vectors []Vector
}

func (m *CollateralDamagePotential) Vectors() []Vector {
	return m.vectors
}

func newCollateralDamagePotential() *CollateralDamagePotential {
	v := new(CollateralDamagePotential)
	v.None = Vector{"Collateral damage potential: none", "N", "CDP:N", 0.0}
	v.Low = Vector{"Collateral damage potential: low", "L", "CDP:L", 0.1}
	v.LowMedium = Vector{"Collateral damage potential: low/medium", "LM", "CDP:LM", 0.3}
	v.MediumHigh = Vector{"Collateral damage potential: medium/high", "MH", "CDP:MH", 0.4}
	v.High = Vector{"Collateral damage potential: high", "H", "CDP:H", 0.5}
	v.NotDefined = Vector{"Collateral damage potential: not defined", "ND", "CDP:ND", 0.0}
	v.vectors = []Vector{v.None, v.Low, v.LowMedium, v.MediumHigh, v.High, v.NotDefined}
	return v
}

type TargetDistribution struct {
	None       Vector
	Low        Vector
	Medium     Vector
	High       Vector
	NotDefined Vector

	vectors []Vector
}

func (m *TargetDistribution) Vectors() []Vector {
	return m.vectors
}

func newTargetDistribution() *TargetDistribution {
	v := new(TargetDistribution)
	v.None = Vector{"Target distribution: none", "N", "TD:N", 0.0}
	v.Low = Vector{"Target distribution: low", "L", "TD:L", 0.25}
	v.Medium = Vector{"Target distribution: medium", "M", "TD:M", 0.75}
	v.High = Vector{"Target distribution: high", "H", "TD:H", 1.0}
	v.NotDefined = Vector{"Target distribution: not defined", "ND", "TD:ND", 0.0}
	v.vectors = []Vector{v.None, v.Low, v.Medium, v.High, v.NotDefined}
	return v
}

type ConfidentialityRequirement struct {
	Low        Vector
	Medium     Vector
	High       Vector
	NotDefined Vector

	vectors []Vector
}

func (m *ConfidentialityRequirement) Vectors() []Vector {
	return m.vectors
}

func newConfidentialityRequirement() *ConfidentialityRequirement {
	v := new(ConfidentialityRequirement)
	v.Low = Vector{"Confidentiality requirement: low", "L", "CR:L", 0.5}
	v.Medium = Vector{"Confidentiality requirement: medium", "M", "CR:M", 1.0}
	v.High = Vector{"Confidentiality requirement: high", "H", "CR:H", 1.51}
	v.NotDefined = Vector{"Confidentiality requirement: not defined", "ND", "CR:ND", 1.0}
	v.vectors = []Vector{v.Low, v.Medium, v.High, v.NotDefined}
	return v
}

type IntegrityRequirement struct {
	Low        Vector
	Medium     Vector
	High       Vector
	NotDefined Vector

	vectors []Vector
}

func (m *IntegrityRequirement) Vectors() []Vector {
	return m.vectors
}

func newIntegrityRequirement() *IntegrityRequirement {
	v := new(IntegrityRequirement)
	v.Low = Vector{"Integrity requirement: low", "L", "IR:L", 0.5}
	v.Medium = Vector{"Integrity requirement: medium", "M", "IR:M", 1.0}
	v.High = Vector{"Integrity requirement: high", "H", "IR:H", 1.51}
	v.NotDefined = Vector{"Integrity requirement: not defined", "ND", "IR:ND", 1.0}
	v.vectors = []Vector{v.Low, v.Medium, v.High, v.NotDefined}
	return v
}

type AvailabilityRequirement struct {
	Low        Vector
	Medium     Vector
	High       Vector
	NotDefined Vector

	vectors []Vector
}

func (m *AvailabilityRequirement) Vectors() []Vector {
	return m.vectors
}

func newAvailabilityRequirement() *AvailabilityRequirement {
	v := new(AvailabilityRequirement)
	v.Low = Vector{"Availability requirement: low", "L", "AR:L", 0.5}
	v.Medium = Vector{"Availability requirement: medium", "M", "AR:M", 1.0}
	v.High = Vector{"Availability requirement: high", "H", "AR:H", 1.51}
	v.NotDefined = Vector{"Availability requirement: not defined", "ND", "AR:ND", 1.0}
	v.vectors = []Vector{v.Low, v.Medium, v.High, v.NotDefined}
	return v
}
