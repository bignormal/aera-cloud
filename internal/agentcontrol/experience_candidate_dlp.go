package agentcontrol

func ScanExperienceCandidate(candidate CanonicalExperienceCandidate) []ExperienceCandidateFinding {
	assets := make([]PublicationTextAsset, 0, len(candidate.Bundle.Assets))
	for _, asset := range candidate.Bundle.Assets {
		assets = append(assets, PublicationTextAsset{Path: asset.Path, Content: asset.Content})
	}
	return scanTextAssets(ExperienceCandidateDLPVersion, assets)
}
