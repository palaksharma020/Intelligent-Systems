(import com.security.evaluation.model.*)
(deftemplate ImpactEvaluation       (declare (from-class ImpactEvaluation)))
(deftemplate VulnEffEvaluation   (declare (from-class VulnEffEvaluation)))
(deftemplate AccPntsEffEvaluation   (declare (from-class AccPntsEffEvaluation)))
(deftemplate PersSecImplEvaluation   (declare (from-class PersSecImplEvaluation)))
(deftemplate SerAcqImplEvaluation   (declare (from-class SerAcqImplEvaluation)))
(deftemplate OverallSecurityEvaluation   (declare (from-class OverallSecurityEvaluation)))

;**************************************************************************************************************
;**************************************************************************************************************
; Rules for Measure 1: Security Budget (program-level) ; Measure Type - Impact ********************************
;**************************************************************************************************************
;**************************************************************************************************************

(defrule get-impact-evaluation-vbad
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal <= 0 && infBudVal <= 0)})
    =>
    (add (new Evaluation "ImpactEvaluation - Very Bad. Immediate Action is Required." 0 " ")))

(defrule cannot-get-impact-evaluation
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal > 0 && infBudVal <= 0)})
    =>
    (add (new Evaluation "ImpactEvaluation - Cannot Generate impact evaluation result.Total information technology budget is 0." 0 " ")))

(defrule cannot-impact-evaluation-infBud_lesthan_secBudget
    "return value of impact security evaluation in terms of percentage."
    ?p <- (ImpactEvaluation { (secBudVal > infBudVal)})
    =>
    (add (new Evaluation "ImpactEvaluation - Cannot Generate impact evaluation result. Security Budget cannot be greater than total information technology budget." 0 " ")))


(defrule get-impact-evaluation-bad1
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal <= 0 && infBudVal > 0)})
    =>
    (add (new Evaluation "ImpactEvaluation - Bad. Total security evaluation budget is 0." ?o.impPercentage " ")))

(defrule get-impact-evaluation-good
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal > 0 && infBudVal > 0 && impPercentage > 0.90 && impPercentage <= 1)})
    =>
    (add (new Evaluation "ImpactEvaluation - Good." ?o.impPercentage " ")))

(defrule get-impact-evaluation-med
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal > 0 && infBudVal > 0 && impPercentage > 0.75 && impPercentage <= 0.90)})
    =>
    (add (new Evaluation "ImpactEvaluation - Medium." ?o.impPercentage " ")))

(defrule get-impact-evaluation-bad
    "return value of impact security evaluation in terms of percentage."
    ?o <- (ImpactEvaluation { (secBudVal > 0 && infBudVal > 0 && impPercentage <= 0.75)})
    =>
    (add (new Evaluation "ImpactEvaluation - Bad." ?o.impPercentage " ")))

;****************************************************************************************************************
;****************************************************************************************************************
; Rules for Measure 2: Vulnerability Management (program-level); Measure Type - Effectiveness/Efficiency
;****************************************************************************************************************
;****************************************************************************************************************

(defrule get-vul-eff-evaluation-vbad
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln <= 0 && idenHighVuln <= 0)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Cannot Generate Vulnerabilities evaluation result.Vulnerabilities count is 0." 0 " ")))

(defrule cannot-vul-eff-evaluation
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln > 0 && idenHighVuln <= 0)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Cannot Generate Vulnerabilities evaluation result.Total Identified vulnerabilities is 0." 0 " ")))

(defrule cannot-vul-eff-evaluation-idVuln_lesthan_mitVuln
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln > idenHighVuln)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Cannot Generate Vulnerabilities evaluation result.Mitigated vulnerabilities cannot be greater than identified vulnerabilities." 0 " ")))

(defrule get-vul-eff-evaluation-bad1
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln <= 0 && idenHighVuln > 0)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Bad. Total mitigated vulnerabilities are <= 0." 0 " ")))

(defrule get-vul-eff-evaluation-good
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln > 0 && idenHighVuln > 0 && mitHighVuln <= idenHighVuln && vulPercentage > 0.90 && vulPercentage <= 1)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Good." ?p.vulPercentage " ")))

(defrule get-vul-eff-evaluation-med
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln > 0 && idenHighVuln > 0 && mitHighVuln <= idenHighVuln && vulPercentage > 0.75 && vulPercentage <= 0.90)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Medium." ?p.vulPercentage " ")))

(defrule get-vul-eff-evaluation-bad
    "return value of impact security evaluation in terms of percentage."
    ?p <- (VulnEffEvaluation { (mitHighVuln > 0 && idenHighVuln > 0 && mitHighVuln <= idenHighVuln && vulPercentage <= 0.75)})
    =>
    (add (new Evaluation "Vulnerability Efficiency Evaluation - Bad." ?p.vulPercentage " ")))

;****************************************************************************************************************
;****************************************************************************************************************
; Rules for Measure 3: Access Control (AC) (system-level); Measure Type - Effectiveness/Efficiency
;****************************************************************************************************************
;****************************************************************************************************************

(defrule cannot-acc-pnt-eff-auto-false-evaluation
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == FALSE})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Cannot Generate Access Point evaluation results as remote access points information is not available." 0 " ")))

(defrule cannot-acc-pnt-eff-unauth-false-evaluation
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE && intDetectSys == FALSE && revAudLogs == FALSE && secIncDatabase == FALSE})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Cannot Generate Access Point evaluation results as unauthorized remote access points information is not available." 0 " ")))

(defrule cannot-acc-pnt-eff-evaluation
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE})
    (AccPntsEffEvaluation {(intDetectSys == TRUE) || (revAudLogs == TRUE) || (secIncDatabase == TRUE)})
    ?q <- (AccPntsEffEvaluation { (remAccPoints <= 0 && unauthAccPnts <= 0)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Cannot Generate Access Point evaluation results as access points are less than or equal to 0." 0 " ")))

(defrule get-acc-pnt-evaluation-vgood
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {(autoToolsUsed == TRUE && intDetectSys == TRUE && revAudLogs == TRUE && secIncDatabase == TRUE)})
    ?p <- (AccPntsEffEvaluation { (remAccPoints > 0 && unauthAccPnts == 0.0)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Very Good." ?p.unAccPntPer " ")))

(defrule cannot-acc-pnt-uap-grt-rap-evaluation
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE})
    (AccPntsEffEvaluation {(intDetectSys == TRUE) || (revAudLogs == TRUE) || (secIncDatabase == TRUE)})
    ?p <- (AccPntsEffEvaluation {(remAccPoints > 0 && unauthAccPnts > 0 && unauthAccPnts > remAccPoints)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Cannot Generate Access Point evaluation results as  Unauthorized access points cannot be greater than remote access points." 0 " ")))

(defrule get-acc-pnt-evaluation-good
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE})
    (AccPntsEffEvaluation {(intDetectSys == TRUE) || (revAudLogs == TRUE) || (secIncDatabase == TRUE)})
    ?p <- (AccPntsEffEvaluation {(remAccPoints > 0 && unauthAccPnts > 0 && unauthAccPnts <= remAccPoints && unAccPntPer > 0 && unAccPntPer <= 0.05)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Good." ?p.unAccPntPer " ")))

(defrule get-acc-pnt-evaluation-med
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE})
    (AccPntsEffEvaluation {(intDetectSys == TRUE) || (revAudLogs == TRUE) || (secIncDatabase == TRUE)})
    ?p <- (AccPntsEffEvaluation { (remAccPoints > 0 && unauthAccPnts > 0 && unauthAccPnts <= remAccPoints && unAccPntPer > 0.05 && unAccPntPer <= 0.1)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Medium." ?p.unAccPntPer " ")))

(defrule get-acc-pnt-evaluation-bad
    "return value of access point security evaluation in terms of percentage."
    (AccPntsEffEvaluation {autoToolsUsed == TRUE})
    (AccPntsEffEvaluation {(intDetectSys == TRUE) || (revAudLogs == TRUE) || (secIncDatabase == TRUE)})
    ?p <- (AccPntsEffEvaluation { (remAccPoints > 0 && unauthAccPnts > 0 && unauthAccPnts <= remAccPoints && unAccPntPer > 0.1)})
    =>
    (add (new Evaluation "Access Points Efficiency Evaluation - Bad." ?p.unAccPntPer " ")))

;****************************************************************************************************************
;****************************************************************************************************************
; Rules for Measure 4: Personnel Security (PS) (program level and system level); Measure Type - Implementation
;****************************************************************************************************************
;****************************************************************************************************************

(defrule get-persSecImpl-evaluation-vbad
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { (noOfScrndPersonnel <= 0 && noOfAuthPersonnel > 0)})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Very Bad. Immediate Action is Required." 0 " ")))

(defrule cannot-get-persSecImpl-evaluation
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { ((noOfScrndPersonnel <= 0 && noOfAuthPersonnel <= 0)|| (noOfAuthPersonnel <= 0))})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Cannot Generate evaluation result.Invalid Data." 0 " ")))

(defrule get-persSecImpl-evaluation-invalid-input
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { (noOfScrndPersonnel > 0 && noOfAuthPersonnel > 0 && noOfAuthPersonnel < noOfScrndPersonnel)})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Cannot Generate evaluation result as number of authorized personnel cannot be less than screened personnel. Please provide correct values." 0 " ")))

(defrule get-persSecImpl-evaluation-good
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { (noOfScrndPersonnel > 0 && noOfAuthPersonnel > 0 && perSecImplPerc > 0.90 && perSecImplPerc <= 1)})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Good." ?o.perSecImplPerc " ")))

(defrule get-persSecImpl-evaluation-med
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { (noOfScrndPersonnel > 0 && noOfAuthPersonnel > 0 && perSecImplPerc > 0.75 && perSecImplPerc <= 0.90)})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Medium." ?o.perSecImplPerc " ")))

(defrule get-persSecImpl-evaluation-bad
    "return value of impact security evaluation in terms of percentage."
    ?o <- (PersSecImplEvaluation { (noOfScrndPersonnel > 0 && noOfAuthPersonnel > 0 && perSecImplPerc <= 0.75)})
    =>
    (add (new Evaluation "Personnel Security Implementation Evaluation - Bad." ?o.perSecImplPerc " ")))

;****************************************************************************************************************
;****************************************************************************************************************
; Rules for Measure 5: System and Services Acquisition (SA)(program-level and system-level);  Measure Type - Implementation
;****************************************************************************************************************
;****************************************************************************************************************

(defrule cannot-get-serAcqImpl-evaluation-noSerSecSpec
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation {(noOfActSerAcqWithSecSpec <= 0)})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Cannot Generate service acquisition implementation evaluation result.No service with security specification." 0 " ")))


(defrule cannot-get-serAcqImpl-evaluation
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation { ((noOfActSerAcqWithSecSpec <= 0 && noOfActSerAcquisition <= 0)|| (noOfActSerAcquisition <= 0))})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Cannot Generate service acquisition implementation evaluation result.Invalid Data." 0 " ")))

(defrule get-serAcqImpl-evaluation-invalid-input
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation { (noOfActSerAcqWithSecSpec > 0 && noOfActSerAcquisition > 0 && noOfActSerAcquisition < noOfActSerAcqWithSecSpec)})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Cannot Generate service acquisition implementation evaluation result. Total number of service acquisition contracts cannot be less than acquisition contracts with security specification.Please provide correct values." 0 " ")))

(defrule get-serAcqImpl-evaluation-good
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation { (noOfActSerAcqWithSecSpec > 0 && noOfActSerAcquisition > 0 && serAcqImplPerc > 0.90 && serAcqImplPerc <= 1)})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Good." ?o.serAcqImplPerc " ")))

(defrule get-serAcqImpl-evaluation-med
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation { (noOfActSerAcqWithSecSpec > 0 && noOfActSerAcquisition > 0 && serAcqImplPerc > 0.75 && serAcqImplPerc <= 0.90)})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Medium." ?o.serAcqImplPerc " ")))

(defrule get-serAcqImpl-evaluation-bad
    "return value of impact security evaluation in terms of percentage."
    ?o <- (SerAcqImplEvaluation { (noOfActSerAcqWithSecSpec > 0 && noOfActSerAcquisition > 0 && serAcqImplPerc <= 0.75)})
    =>
    (add (new Evaluation "System & Service Acquisition Evaluation - Bad." ?o.serAcqImplPerc " ")))

;****************************************************************************************************************
;****************************************************************************************************************
; Rules for Cumulative Evaluation
;****************************************************************************************************************
;****************************************************************************************************************

(defrule get-total-cumm-evaluation-very-good
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation { ((impPercentage > 0.90 && impPercentage <= 1)&& (vulPercentage > 0.90 && vulPercentage <= 1)&&(perSecImplPerc > 0.90 && perSecImplPerc <= 1)&&(serAcqImplPerc > 0.90 && serAcqImplPerc <= 1)&&(unAccPntPer > 0.90 && unAccPntPer <= 1) && (overallSecPer > 0.90 && overallSecPer <= 1))} )
    =>
    (add (new Evaluation "Overall Security Evaluation - Very Good." ?o.overallSecPer "# Should maintain the current security level by contiuously implementing best security practices at program and organizatial level.")))

(defrule get-total-cumm-evaluation-good
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {overallSecPer > 0.75 && overallSecPer <= 0.90} )
    =>
    (add (new Evaluation "Overall Security Evaluation - Good." ?o.overallSecPer "# Should incorporate best practices and regular information resources auditing to improve overall security.")))

(defrule get-total-cumm-evaluation-med
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {overallSecPer > 0.50 && overallSecPer <= 0.75} )
    =>
    (add (new Evaluation "Overall Security Evaluation - Medium." ?o.overallSecPer "# Should take immediate action to improve security metric values. Consult an security information security analyst to implement more security measures.")))

(defrule get-total-cumm-evaluation-bad
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {overallSecPer <= 0.50} )
    =>
    (add (new Evaluation "Overall Security Evaluation - Bad." ?o.overallSecPer "# Should consult a information security analyst on high priority and reconstruct new security plan and start implementing it.")))

(defrule get-total-cumm-evaluation-good1
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {((overallSecPer > 0.75 && overallSecPer <= 1) && (impPercentage < 0.90 || vulPercentage < 0.90 || perSecImplPerc < 0.90 || serAcqImplPerc < 0.90 || unAccPntPer < 0.90))} )
    =>
    (add (new Evaluation "Recommendations" ?o.overallSecPer "# Higher Cyber Security measures.# Update all aplications with latest version.")))

(defrule get-total-cumm-evaluation-med1
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {((overallSecPer > 0.50 && overallSecPer <= 0.75) && (impPercentage < 0.75 || vulPercentage < 0.75 || perSecImplPerc < 0.75 || serAcqImplPerc < 0.75 || unAccPntPer < 0.75))} )
    =>
    (add (new Evaluation "Recommendations" ?o.overallSecPer "# Better strategies for authentication and authorization.# Inforce privacy standards at organization and project level.# Take frequent backups for all organization and program level softwares.")))

(defrule get-total-cumm-evaluation-bad1
    "return value of cummulative security evaluation in terms of percentage."
    ?o <- (OverallSecurityEvaluation {((overallSecPer < 0.50) && (impPercentage < 0.50 || vulPercentage < 0.50 || perSecImplPerc < 0.50 || serAcqImplPerc < 0.50 || unAccPntPer < 0.50))} )
    =>
    (add (new Evaluation "Recommendations" ?o.overallSecPer "# Employ and regularly check security sensor equippments.# Enforce standarized rules for security practices ate organization and program level.# Use password managers for accessing critical software system.# Conduct training session for security awarness in the organization.")))
