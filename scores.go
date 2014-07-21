package cvss

import "math"

// Round to one decimal.
func round(x float64) float64 {
	var rounder float64
	pow := math.Pow(10, 1.0)
	intermed := x * pow

	if intermed < 0.0 {
		intermed -= 0.5
	} else {
		intermed += 0.5
	}
	rounder = float64(int64(intermed))

	return rounder / float64(pow)
}

func getBaseScore(impact, base_exploitability, impact_mod float64) float64 {
	return round(
		((0.6 * impact) + (0.4 * base_exploitability) - 1.5) * impact_mod)
}

// Score returns the computed scores for the given CVSS model.
func (c CVSS) Score() Score {
	return Score{
		Base:          c.baseScore(),
		Temporal:      c.temporalScore(),
		Environmental: c.environmentalScore()}
}

func (c CVSS) score(defaultValue float64, g group) float64 {
	for _, metric := range c {
		if groups[metric] == g {
			return scores[metric]
		}
	}
	return defaultValue
}

func (c CVSS) baseScore() float64 {
	return getBaseScore(c.impact(), c.baseExploitability(), c.impactMod())
}

func (c CVSS) impact() float64 {
	return 10.41 * (1.0 - (1.0-c.confidentialityImpact())*
		(1.0-c.integrityImpact())*
		(1.0-c.availabilityImpact()))
}

func (c CVSS) confidentialityImpact() float64 {
	return c.score(0.0, confidentiality)
}

func (c CVSS) integrityImpact() float64 {
	return c.score(0.0, integrity)
}

func (c CVSS) availabilityImpact() float64 {
	return c.score(0.0, availability)
}

func (c CVSS) baseExploitability() float64 {
	return 20 * c.accessVectorScore() * c.accessComplexityScore() * c.authenticationScore()
}

func (c CVSS) accessVectorScore() float64 {
	return c.score(0.0, accessVector)
}

func (c CVSS) accessComplexityScore() float64 {
	return c.score(0.0, accessComplexity)
}

func (c CVSS) authenticationScore() float64 {
	return c.score(0.0, authentication)
}

func (c CVSS) impactMod() float64 {
	if c.impact() == 0.0 {
		return 0.0
	}
	return 1.176
}

func (c CVSS) temporalScore() float64 {
	return c.getTemporalScore(getBaseScore(c.impact(), c.baseExploitability(), c.impactMod()))
}

func (c CVSS) getTemporalScore(baseScore float64) float64 {
	return round(baseScore * c.temporalExploitability() * c.remediationLevel() * c.reportConfidence())
}

func (c CVSS) temporalExploitability() float64 {
	return c.score(scores[Exploitability_NotDefined], exploitability)
}

func (c CVSS) remediationLevel() float64 {
	return c.score(scores[RemediationLevel_NotDefined], remediationLevel)
}

func (c CVSS) reportConfidence() float64 {
	return c.score(scores[ReportConfidence_NotDefined], reportConfidence)
}

func (c CVSS) environmentalScore() float64 {
	return round((c.adjustedTemporal() + (10-c.adjustedTemporal())*c.collateralDamagePotential()) * c.targetDistribution())
}

func (c CVSS) adjustedTemporal() float64 {
	return c.getTemporalScore(getBaseScore(c.adjustedImpact(), c.baseExploitability(), c.adjustedImpactMod()))
}

func (c CVSS) adjustedImpact() float64 {
	return math.Min(10,
		10.41*(1-(1-c.confidentialityImpact()*c.confidentialityRequirement())*(1-c.integrityImpact()*c.integrityRequirement())*(1-c.availabilityImpact()*c.availabilityRequirement())))
}

func (c CVSS) adjustedImpactMod() float64 {
	if c.adjustedImpact() == 0.0 {
		return 0.0
	}
	return 1.176
}

func (c CVSS) collateralDamagePotential() float64 {
	return c.score(scores[CollateralDamagePotential_NotDefined], collateralDamagePotential)
}

func (c CVSS) targetDistribution() float64 {
	return c.score(scores[TargetDistribution_NotDefined], targetDistribution)
}

func (c CVSS) confidentialityRequirement() float64 {
	return c.score(scores[ConfidentialityRequirement_NotDefined], confidentialityRequirement)
}

func (c CVSS) integrityRequirement() float64 {
	return c.score(scores[IntegrityRequirement_NotDefined], integrityRequirement)
}

func (c CVSS) availabilityRequirement() float64 {
	return c.score(scores[AvailabilityRequirement_NotDefined], availabilityRequirement)
}
