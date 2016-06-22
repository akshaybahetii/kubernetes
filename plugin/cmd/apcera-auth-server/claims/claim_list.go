// Copyright 2012-2013 Apcera Inc. All rights reserved.

package claims

import (
	"bytes"
	"fmt"
)

type ClaimList []*Claim

// Gets all claims that match the specified type. It also matches for claims
// issued by the Auth Server...
//TODO(lev) remove the ok output, it's redundant
func (cl ClaimList) GetByType(claimType string) (matches ClaimList, ok bool) {
	//	log.Debugf("Getting claims by claimType: %s", claimType)
	matches = ClaimList{}
	for _, claim := range cl {
		if string(claim.Type) != claimType {
			continue
		}

		//		log.Debugf("Found a claim of type %s : %s", claimType, claim)
		matches = append(matches, claim)
	}
	if len(matches) == 0 {
		return nil, false
	}
	return matches, true
}

func (cl ClaimList) GetByIssuerAndType(iss, ct string) (ClaimList, bool) {
	byType, ok := cl.GetByType(ct)
	if !ok {
		return nil, false
	}
	matches := ClaimList{}
	for _, cl := range byType {
		if cl.Issuer == iss {
			matches = append(matches, cl)
		}
	}
	if len(matches) == 0 {
		return nil, false
	}
	return matches, true
}

// NewClaimList hides the definition of ClaimList from external callers
func NewClaimList(size int) ClaimList {
	return make(ClaimList, size)
}

func (cl ClaimList) String() string {
	buf := bytes.Buffer{}
	for _, c := range cl {
		_, _ = buf.WriteString(fmt.Sprintf(
			"{%s->%s=%v}",
			c.Issuer, c.Type, c.Value))
	}
	return buf.String()
}
