package com.security.service;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import com.security.model.AccPntsEffEvaluation;
import com.security.model.Evaluation;
import com.security.model.ImpactEvaluation;
import com.security.model.OverallSecurityEvaluation;
import com.security.model.PersSecImplEvaluation;
import com.security.model.SerAcqImplEvaluation;
import com.security.model.UserInput;
import com.security.model.UserInputInt;
import com.security.model.VulnEffEvaluation;
import com.security.engine.SecurityEngine;
import jess.JessException;

public class SecurityService {

	/*
	 * Measure 1: Security Budget (program-level) ; Measure Type - Impact
	 */
	private ImpactEvaluation impactEvaluationObj;
	private VulnEffEvaluation VulnEffEvalObj;
	private AccPntsEffEvaluation accPntsEffEvalObj;
	private PersSecImplEvaluation persSecImplEvaluation;
	private SerAcqImplEvaluation serAcqImplEvaluation;
	private List<String> recommendationList;

	private List<Evaluation> getImpactEvaluationList(SecurityEngine secEngine,
			double secBudVal, double infBudVal) throws JessException {

		impactEvaluationObj = getImpactEvalObject(secBudVal, infBudVal);
		/* Get impact evaluation in percentage as per rules. */
		List<Evaluation> impactEvalList = getEvaluationforImpact(secEngine,
				impactEvaluationObj);
		return impactEvalList;
	}

	/*
	 * Measure 2: Vulnerability Management (program-level); Measure Type -
	 * Effectiveness/Efficiency
	 */

	private List<Evaluation> getVulEffEvalList(SecurityEngine secEngine,
			double idenHighVuln, double mitHighVuln) throws JessException {

		VulnEffEvalObj = getVulEffEvalObject(idenHighVuln, mitHighVuln);
		/*
		 * Get vulnerability efficiency evaluation in percentage as per rules.
		 */
		List<Evaluation> VulEffEvalList = getEvaluationforVulnEfficiency(
				secEngine, VulnEffEvalObj);
		return VulEffEvalList;

	}

	/*
	 * Measure 3: Access Control (AC) (system-level); Measure Type -
	 * Effectiveness/Efficiency
	 */

	private List<Evaluation> getAccPntsEffEvalList(SecurityEngine secEngine,
			String autoToolsUsed, double remAccPoints, String intDetectSys,
			String revAudLogs, String secIncDatabase, double unauthAccPnts)
			throws JessException {

		accPntsEffEvalObj = getAccPntsEffEvalObject(
				autoToolsUsed, remAccPoints, intDetectSys, revAudLogs,
				secIncDatabase, unauthAccPnts);

		List<Evaluation> accPntsEffEvalList = getEvaluationforAccPntEfficiency(
				secEngine, accPntsEffEvalObj);

		return accPntsEffEvalList;
	}

	/*
	 * Measure 4: Personnel Security (PS) (program level and system level);
	 * Measure Type - Implementation
	 */

	private List<Evaluation> getPerSecImplEvalList(SecurityEngine secEngine,
			double noOfAuthPersonnel, double noOfScrndPersonnel)
			throws JessException {

		persSecImplEvaluation = getPerSecImplEvalObject(noOfAuthPersonnel,
				noOfScrndPersonnel);

		List<Evaluation> perSecImplEvalList = getEvaluationforPersSecImpl(
				secEngine, persSecImplEvaluation);
		return perSecImplEvalList;
	}

	/*
	 * Measure 5: System and Services Acquisition (SA) (program-level and
	 * system-level); Measure Type - Implementation
	 */

	private List<Evaluation> getSerAcqImplEvalList(SecurityEngine secEngine,
			double noOfActSerAcquisition, double noOfActSerAcqWithSecSpec)
			throws JessException {

		serAcqImplEvaluation = getSerAcqImplEvalObject(noOfActSerAcquisition,
				noOfActSerAcqWithSecSpec);
		List<Evaluation> serAcqImplEvalList = getEvaluationforSerAcqImpl(
				secEngine, serAcqImplEvaluation);
		return serAcqImplEvalList;
	}

	private List<Evaluation> getOverallSecEvalList(SecurityEngine secEngine,
			ImpactEvaluation impactEvaluationObj,
			VulnEffEvaluation VulnEffEvalObj,
			AccPntsEffEvaluation accPntsEffEvalObj,
			PersSecImplEvaluation persSecImplEvaluation,
			SerAcqImplEvaluation serAcqImplEvaluation) throws JessException {

		List<Evaluation> overAllEvalList = getOverallSecurityEvaluation(
				secEngine, impactEvaluationObj, VulnEffEvalObj,
				accPntsEffEvalObj, persSecImplEvaluation, serAcqImplEvaluation);

		recommendationList = getAllRecommendations(overAllEvalList);
		return overAllEvalList;
	}

	private List<String> getAllRecommendations(List<Evaluation> overAllEvalList) {

		List<String> allRecommList = new ArrayList<String>();

		for (Evaluation eval : overAllEvalList) {
			if (!eval.getRecommendations().equals(" ")) {
				String rec = eval.getRecommendations();
				String[] arr = rec.split("#");
				for (String s : arr) {
					if (s.length() != 0) {
						allRecommList.add(s);
					}
				}
			}

		}
		return allRecommList;
	}

	public List<String> getRecommendationList() {
		return recommendationList;
	}

	public List<Evaluation> getAllEvaluationList(UserInput userInput)
			throws JessException {

		List<Evaluation> EvalRecList = new ArrayList<Evaluation>();
		/* Create instance of engine object */
		SecurityEngine secEngine = new SecurityEngine();

		UserInputInt userInputInt = new UserInputInt(
				userInput.getImpact_eval_a1(), userInput.getImpact_eval_a2(),
				userInput.getVuln_eval_a1(), userInput.getVuln_eval_a2(),
				userInput.getAcpt_eval_a1(), userInput.getAcpt_eval_a2(),
				userInput.getAcpt_eval_a3(), userInput.getAcpt_eval_a4(),
				userInput.getAcpt_eval_a5(), userInput.getAcpt_eval_a6(),
				userInput.getPsi_eval_a1(), userInput.getPsi_eval_a2(),
				userInput.getSacq_eval_a1(), userInput.getSacq_eval_a2());

		List<Evaluation> impactEvalList = getImpactEvaluationList(secEngine,
				userInputInt.getImpact_eval_a1(),
				userInputInt.getImpact_eval_a2());

		List<Evaluation> vulEffEvalList = getVulEffEvalList(secEngine,
				userInputInt.getVuln_eval_a1(), userInputInt.getVuln_eval_a2());

		List<Evaluation> accPntsEffEvalList = getAccPntsEffEvalList(secEngine,
				userInputInt.getAcpt_eval_a1(), userInputInt.getAcpt_eval_a2(),
				userInputInt.getAcpt_eval_a3(), userInputInt.getAcpt_eval_a4(),
				userInputInt.getAcpt_eval_a5(), userInputInt.getAcpt_eval_a6());

		List<Evaluation> perSecImplEvalList = getPerSecImplEvalList(secEngine,
				userInputInt.getPsi_eval_a1(), userInputInt.getPsi_eval_a2());

		List<Evaluation> serAcqImplEvalList = getSerAcqImplEvalList(secEngine,
				userInputInt.getSacq_eval_a1(), userInputInt.getSacq_eval_a2());

		List<Evaluation> overAllEvalList = getOverallSecEvalList(secEngine,
				impactEvaluationObj, VulnEffEvalObj, accPntsEffEvalObj,
				persSecImplEvaluation, serAcqImplEvaluation);

		EvalRecList.addAll(impactEvalList);
		EvalRecList.addAll(vulEffEvalList);
		EvalRecList.addAll(accPntsEffEvalList);
		EvalRecList.addAll(perSecImplEvalList);
		EvalRecList.addAll(serAcqImplEvalList);
		EvalRecList.addAll(overAllEvalList);

		return EvalRecList;
	}

	private static List<Evaluation> getOverallSecurityEvaluation(
			SecurityEngine secEngine, ImpactEvaluation impactEvaluationObj,
			VulnEffEvaluation vulnEffEvalObj,
			AccPntsEffEvaluation accPntsEffEvalObj,
			PersSecImplEvaluation persSecImplEvaluation,
			SerAcqImplEvaluation serAcqImplEvaluation) {

		Iterator overallsecEvalItr;
		List<Evaluation> overAllEvalList = new ArrayList<Evaluation>();

		OverallSecurityEvaluation overallSecEvalObj = new OverallSecurityEvaluation(
				impactEvaluationObj.getImpPercentage(),
				vulnEffEvalObj.getVulPercentage(),
				accPntsEffEvalObj.getUnAccPntPer(),
				persSecImplEvaluation.getPerSecImplPerc(),
				serAcqImplEvaluation.getSerAcqImplPerc());

		try {
			overallsecEvalItr = secEngine.run(overallSecEvalObj);
			while (overallsecEvalItr.hasNext()) {
				overAllEvalList.add((Evaluation) overallsecEvalItr.next());
			}

		} catch (JessException e) {
			e.printStackTrace();
		}
		return overAllEvalList;
	}

	private static SerAcqImplEvaluation getSerAcqImplEvalObject(
			double noOfActSerAcquisition, double noOfActSerAcqWithSecSpec) {

		/* create object of PersSecImpEvaluation class */
		SerAcqImplEvaluation serAcqImplEvaluation = new SerAcqImplEvaluation(
				noOfActSerAcquisition, noOfActSerAcqWithSecSpec);

		return serAcqImplEvaluation;
	}

	private static PersSecImplEvaluation getPerSecImplEvalObject(
			double noOfAuthPersonnel, double noOfScrndPersonnel) {

		/* create object of PersSecImpEvaluation class */
		PersSecImplEvaluation persSecImplEvaluation = new PersSecImplEvaluation(
				noOfScrndPersonnel, noOfAuthPersonnel);

		return persSecImplEvaluation;
	}

	private static AccPntsEffEvaluation getAccPntsEffEvalObject(
			String autoToolsUsedSt, double remAccPoints, String intDetectSysSt,
			String revAudLogsSt, String secIncDatabaseSt, double unauthAccPnts) {

		AccPntsEffEvaluation accPntsEffEvalObj = null;

		/*
		 * Q1. Does the organization use automated tools to maintain an
		 * up-to-that identifies all remote access points (CM-2)?
		 */

		boolean autoToolsUsed = convertStringToBoolean(autoToolsUsedSt);
		;

		/*
		 * Q2. How many remote access points exist in the organization’s
		 * network?
		 */

		/*
		 * Q3. Does the organization employ Intrusion Detection Systems (IDS) to
		 * monitor traffic traversing remote access points (SI-4)?
		 */

		boolean intDetectSys = convertStringToBoolean(intDetectSysSt);

		/*
		 * Q4. Does the organization collect and review audit logs associated
		 * with all remote access points (AU-6)?
		 */

		boolean revAudLogs = convertStringToBoolean(revAudLogsSt);

		/*
		 * Q5. Does the organization maintain a security incident database that
		 * identifies standardized incident categories for each incident (IR-5)?
		 */

		boolean secIncDatabase = convertStringToBoolean(secIncDatabaseSt);

		/*
		 * Q6. Based on reviews of the incident database, IDS logs and alerts,
		 * and/or appropriate remote access point log files, how many access
		 * points have been used to gain unauthorized access within the
		 * reporting period?
		 */

		/* create object of AccPntsEffEvaluation class */
		accPntsEffEvalObj = new AccPntsEffEvaluation(remAccPoints,
				autoToolsUsed, intDetectSys, revAudLogs, secIncDatabase,
				unauthAccPnts);

		return accPntsEffEvalObj;
	}

	private static VulnEffEvaluation getVulEffEvalObject(double idenHighVuln,
			double mitHighVuln) {

		/* create object of VulnEffEvaluation class */
		VulnEffEvaluation VulnEffEvalObj = new VulnEffEvaluation(mitHighVuln,
				idenHighVuln);
		return VulnEffEvalObj;
	}

	private static ImpactEvaluation getImpactEvalObject(double secBudVal,
			double infBudVal) {
		ImpactEvaluation impactEvaluationObj = new ImpactEvaluation(secBudVal,
				infBudVal);
		return impactEvaluationObj;
	}

	private static Boolean convertStringToBoolean(String autoToolsUsedString) {
		Boolean boolVal = false;
		if ((autoToolsUsedString.equals("Y"))
				|| (autoToolsUsedString.equals("y"))) {
			boolVal = true;
		}
		return boolVal;
	}

	private static List<Evaluation> getEvaluationforSerAcqImpl(
			SecurityEngine secEngine, SerAcqImplEvaluation serAcqImplEvaluation)
			throws JessException {

		Iterator serAcqImplEvalItr;
		List<Evaluation> serAcqImplEvalList = new ArrayList<Evaluation>();

		serAcqImplEvalItr = secEngine.run(serAcqImplEvaluation);

		while (serAcqImplEvalItr.hasNext()) {
			serAcqImplEvalList.add((Evaluation) serAcqImplEvalItr.next());

		}
		return serAcqImplEvalList;
	}

	private static List<Evaluation> getEvaluationforPersSecImpl(
			SecurityEngine secEngine,
			PersSecImplEvaluation persSecImplEvaluation) throws JessException {

		Iterator persSecImplEvalItr;
		List<Evaluation> persSecImplEvalList = new ArrayList<Evaluation>();
		persSecImplEvalItr = secEngine.run(persSecImplEvaluation);

		while (persSecImplEvalItr.hasNext()) {
			persSecImplEvalList.add((Evaluation) persSecImplEvalItr.next());
		}
		return persSecImplEvalList;
	}

	private static List<Evaluation> getEvaluationforAccPntEfficiency(
			SecurityEngine secEngine, AccPntsEffEvaluation accPntsEffEvalObj)
			throws JessException {

		Iterator accPntsEffEvalItr;
		List<Evaluation> accPntsEffEvalList = new ArrayList<Evaluation>();

		accPntsEffEvalItr = secEngine.run(accPntsEffEvalObj);

		while (accPntsEffEvalItr.hasNext()) {
			accPntsEffEvalList.add((Evaluation) accPntsEffEvalItr.next());
		}
		return accPntsEffEvalList;
	}

	private static List<Evaluation> getEvaluationforVulnEfficiency(
			SecurityEngine secEngine, VulnEffEvaluation vulnEffEvalObj)
			throws JessException {

		Iterator vulEffEvalItr;
		List<Evaluation> vulEffEvalList = new ArrayList<Evaluation>();

		vulEffEvalItr = secEngine.run(vulnEffEvalObj);

		while (vulEffEvalItr.hasNext()) {
			vulEffEvalList.add((Evaluation) vulEffEvalItr.next());

		}
		return vulEffEvalList;
	}

	private static List<Evaluation> getEvaluationforImpact(
			SecurityEngine secEngine, ImpactEvaluation impEvalObj)
			throws JessException {

		Iterator impactEvalItr;
		List<Evaluation> impactEvalList = new ArrayList<Evaluation>();

		impactEvalItr = secEngine.run(impEvalObj);

		while (impactEvalItr.hasNext()) {
			impactEvalList.add((Evaluation) impactEvalItr.next());
		}

		return impactEvalList;
	}

}
