[![Build Status](https://travis-ci.org/attwad/gocvss.svg?branch=master)](https://travis-ci.org/attwad/gocvss)

gocvss
======

Library to parse Common Vulerability Sscoring System vectors and generate scores

Usage
=====

Let's take CVE-2002-0392 as an example, suppose you already have a base vector, you can parse it with
```go
var c, err = Parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
if err != nil {
		t.Errorf("New from vector failed: %v", err)
}
```
And then add the different vectors based on your environment:
```go
// Temporal vectors
c = append(c, Exploitability_Functional)
c = append(c, RemediationLevel_OfficialFix)
c = append(c, ReportConfidence_Confirmed)
// Environmental vectors
c = append(c, CollateralDamagePotential_High)
c = append(c, TargetDistribution_High)
c = append(c, ConfidentialityRequirement_High)
c = append(c, IntegrityRequirement_High)
c = append(c, AvailabilityRequirement_High)
```
Then compute the scores and/or display them:
```go
s := c.Score()
//-> Score{7.8, 6.4, 9.2}

fmt.Print(c.String())
        base score                     7.800000
          access vector                1.000000
          access complexity            0.710000
          authentication               0.704000
          confidentiality impact       0.000000
          integrity impact             0.000000
          availability impact          0.660000

        temporal score                 6.400000
          exploitability               0.950000
          remediation level            0.870000
          report confidence            1.000000

        environmental score            9.200000
          collateral damage potential  0.500000
          target distribution          1.000000
          confidentiality requirement  1.000000
          integrity requirement        1.510000
          availability requirement     1.510000
```
