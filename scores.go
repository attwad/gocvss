package cvss

import "math"

func round(x float64, prec int) float64 {
	var rounder float64
	pow := math.Pow(10, float64(prec))
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
		((0.6*impact)+(0.4*base_exploitability)-1.5)*impact_mod, 1)
}

// Returns the computed scores for the given Cvss model.
func (c *Cvss) Score() Score {
	return Score{
		Base:          c.baseScore(),
		Temporal:      c.temporalScore(),
		Environmental: c.environmentalScore()}
}

func (c *Cvss) baseScore() float64 {
	return getBaseScore(c.impact(), c.baseExploitability(), c.impactMod())
}

func (c *Cvss) impact() float64 {
	return 10.41 * (1.0 - (1.0-c.confidentialityImpact())*
		(1.0-c.integrityImpact())*
		(1.0-c.availabilityImpact()))
}

func (c *Cvss) confidentialityImpact() float64 {
	return c.getMetricScore(C, 0.0)
}

func (c *Cvss) integrityImpact() float64 {
	return c.getMetricScore(I, 0.0)
}

func (c *Cvss) availabilityImpact() float64 {
	return c.getMetricScore(A, 0.0)
}

func (c *Cvss) baseExploitability() float64 {
	return 20 * c.accessVectorScore() * c.accessComplexityScore() * c.authenticationScore()
}

func (c *Cvss) accessVectorScore() float64 {
	return c.getMetricScore(AV, 0.0)
}

func (c *Cvss) accessComplexityScore() float64 {
	return c.getMetricScore(AC, 0.0)
}

func (c *Cvss) authenticationScore() float64 {
	return c.getMetricScore(Au, 0.0)
}

func (c *Cvss) impactMod() float64 {
	if c.impact() == 0.0 {
		return 0.0
	}
	return 1.176
}

func (c *Cvss) temporalScore() float64 {
	return c.getTemporalScore(getBaseScore(c.impact(), c.baseExploitability(), c.impactMod()))
}

func (c *Cvss) getTemporalScore(baseScore float64) float64 {
	return round(baseScore*c.temporalExploitability()*c.remediationLevel()*c.reportConfidence(), 1)
}

func (c *Cvss) temporalExploitability() float64 {
	return c.getMetricScore(E, E.NotDefined.score)
}

func (c *Cvss) remediationLevel() float64 {
	return c.getMetricScore(RL, RL.NotDefined.score)
}

func (c *Cvss) reportConfidence() float64 {
	return c.getMetricScore(RC, RC.NotDefined.score)
}

func (c *Cvss) getMetricScore(m metric, defaultValue float64) float64 {
	for _, vec := range m.Vectors() {
		if _, ok := c.vectors[vec]; ok {
			return vec.score
		}
	}
	return defaultValue
}

func (c *Cvss) environmentalScore() float64 {
	return round((c.adjustedTemporal()+(10-c.adjustedTemporal())*c.collateralDamagePotential())*c.targetDistribution(), 1)
}

func (c *Cvss) adjustedTemporal() float64 {
	return c.getTemporalScore(getBaseScore(c.adjustedImpact(), c.baseExploitability(), c.adjustedImpactMod()))
}

func (c *Cvss) adjustedImpact() float64 {
	return math.Min(10,
		10.41*(1-(1-c.confidentialityImpact()*c.confidentialityRequirement())*(1-c.integrityImpact()*c.integrityRequirement())*(1-c.availabilityImpact()*c.availabilityRequirement())))
}

func (c *Cvss) adjustedImpactMod() float64 {
	if c.adjustedImpact() == 0.0 {
		return 0.0
	}
	return 1.176
}

func (c *Cvss) collateralDamagePotential() float64 {
	return c.getMetricScore(CDP, CDP.NotDefined.score)
}

func (c *Cvss) targetDistribution() float64 {
	return c.getMetricScore(TD, TD.NotDefined.score)
}

func (c *Cvss) confidentialityRequirement() float64 {
	return c.getMetricScore(CR, CR.NotDefined.score)
}

func (c *Cvss) integrityRequirement() float64 {
	return c.getMetricScore(IR, IR.NotDefined.score)
}

func (c *Cvss) availabilityRequirement() float64 {
	return c.getMetricScore(AR, AR.NotDefined.score)
}
