package com.security.engine;

import jess.*;

import java.util.Iterator;

import com.security.model.AccPntsEffEvaluation;
import com.security.model.Evaluation;
import com.security.model.ImpactEvaluation;
import com.security.model.OverallSecurityEvaluation;
import com.security.model.PersSecImplEvaluation;
import com.security.model.SerAcqImplEvaluation;
import com.security.model.VulnEffEvaluation;

public class SecurityEngine {
	private Rete engine;
	private WorkingMemoryMarker marker;

	public SecurityEngine() throws JessException {
		// Create a Jess rule engine
		engine = new Rete();
		engine.reset();

		// Load the security rules
		engine.batch("security_rules.clp");

		// Mark end of data for later
		marker = engine.mark();
	}

	public Iterator<Evaluation> run(ImpactEvaluation impEvalObj) throws JessException {
		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadImpEvalObj(impEvalObj);

		// Fire the rules that apply.
		engine.run();

		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		return it;
	}

	public Iterator<Evaluation> run(VulnEffEvaluation vulEffObj) throws JessException {
		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadVulEffEvalObj(vulEffObj);

		// Fire the rules that apply.
		engine.run();

		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		return it;
	}

	public Iterator<Evaluation> run(AccPntsEffEvaluation accPntsEffEvalObj)
			throws JessException {

		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadAccPntEffEvalObj(accPntsEffEvalObj);

		// Fire the rules that apply.
		engine.run();
		
		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		return it;
	}

	public Iterator<Evaluation> run(PersSecImplEvaluation persSecImplEvalObj)
			throws JessException {

		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadPerSecImplEvalObj(persSecImplEvalObj);

		// Fire the rules that apply.
		engine.run();

		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		return it;
	}

	public Iterator<Evaluation> run(SerAcqImplEvaluation serAcqImplEvalObj)
			throws JessException {

		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadSerAcqImplEvalObj(serAcqImplEvalObj);

		// Fire the rules that apply.
		engine.run();

		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		return it;
	}

	public Iterator run(OverallSecurityEvaluation overallSecEvalObj)
			throws JessException {

		// Remove any previous order data, leaving only current data
		engine.resetToMark(marker);

		loadOverallSecEvalObj(overallSecEvalObj);

		// Fire the rules that apply.
		engine.run();

		Iterator it = engine.getObjects(new Filter() {
            public boolean accept(Object o) {
                return o instanceof Evaluation;
            }
        });
		
		return it;
		
		
		
	}

	private void loadOverallSecEvalObj(
			OverallSecurityEvaluation overallSecEvalObj) throws JessException {

		if (overallSecEvalObj != null) {
			// Add the overallSecEvalObj and its contents to working memory
			engine.add(overallSecEvalObj);
			engine.add(overallSecEvalObj.getImpPercentage());
			engine.add(overallSecEvalObj.getPerSecImplPerc());
			engine.add(overallSecEvalObj.getSerAcqImplPerc());
			engine.add(overallSecEvalObj.getUnAccPntPer());
			engine.add(overallSecEvalObj.getVulPercentage());
		}
	}

	private void loadSerAcqImplEvalObj(SerAcqImplEvaluation serAcqImplEvalObj)
			throws JessException {

		if (serAcqImplEvalObj != null) {
			// Add the serAcqImplEvalObj and its contents to working memory
			engine.add(serAcqImplEvalObj);
			engine.add(serAcqImplEvalObj.getNoOfActSerAcquisition());
			engine.add(serAcqImplEvalObj.getNoOfActSerAcqWithSecSpec());
			engine.add(serAcqImplEvalObj.getSerAcqImplPerc());
		}

	}

	private void loadAccPntEffEvalObj(AccPntsEffEvaluation accPntsEffEvalObj)
			throws JessException {

		if (accPntsEffEvalObj != null) {
			// Add the accPntsEffEvalObj and its contents to working memory
			engine.add(accPntsEffEvalObj);
			engine.add(accPntsEffEvalObj.getRemAccPoints());
			engine.add(accPntsEffEvalObj.getUnauthAccPnts());
			engine.add(accPntsEffEvalObj.isAutoToolsUsed());
			engine.add(accPntsEffEvalObj.isIntDetectSys());
			engine.add(accPntsEffEvalObj.isRevAudLogs());
			engine.add(accPntsEffEvalObj.isSecIncDatabase());
			engine.add(accPntsEffEvalObj.getUnAccPntPer());
		}
	}

	private void loadVulEffEvalObj(VulnEffEvaluation vulEffObj)
			throws JessException {

		if (vulEffObj != null) {
			// Add the vulEffObj and its contents to working memory
			engine.add(vulEffObj);
			engine.add(vulEffObj.getMitHighVuln());
			engine.add(vulEffObj.getIdenHighVuln());
			engine.add(vulEffObj.getVulPercentage());
		}

	}

	private void loadImpEvalObj(ImpactEvaluation impEvalObj)
			throws JessException {

		if (impEvalObj != null) {
			// Add the impEvalObj and its contents to working memory
			engine.add(impEvalObj);
			engine.add(impEvalObj.getSecBudVal());
			engine.add(impEvalObj.getInfBudVal());
			engine.add(impEvalObj.getImpPercentage());

		}
	}

	private void loadPerSecImplEvalObj(PersSecImplEvaluation persSecImplEvalObj)
			throws JessException {

		if (persSecImplEvalObj != null) {
			// Add the persSecImplEvalObj and its contents to working memory
			engine.add(persSecImplEvalObj);
			engine.add(persSecImplEvalObj.getNoOfAuthPersonnel());
			engine.add(persSecImplEvalObj.getNoOfScrndPersonnel());
			engine.add(persSecImplEvalObj.getPerSecImplPerc());

		}
	}

}