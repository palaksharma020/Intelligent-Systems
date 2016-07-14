package com.security.model;

import java.util.List;

public class EvalRecomdReponse {

	private List<Evaluation> evaluationList;
	private List<String> recommendationList;

	public EvalRecomdReponse(List<Evaluation> evaluationList,
			List<String> recommendationList) {
		super();
		this.evaluationList = evaluationList;
		this.recommendationList = recommendationList;
	}

	public List<Evaluation> getEvaluationList() {
		return evaluationList;
	}

	public List<String> getRecommendationList() {
		return recommendationList;
	}

	@Override
	public String toString() {
		return "EvalRecomdReponse [evaluationList=" + evaluationList
				+ ", recommendationList=" + recommendationList + "]";
	}

}
