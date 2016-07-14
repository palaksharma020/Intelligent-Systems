package com.security.servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jess.JessException;

import org.json.JSONException;
import org.json.JSONObject;

import com.google.gson.Gson;
import com.security.model.EvalRecomdReponse;
import com.security.model.Evaluation;
import com.security.model.UserInput;
import com.security.service.SecurityService;

/**
 * Servlet implementation class SecurityServlet
 */
@WebServlet("/SecurityServlet")
public class SecurityServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public SecurityServlet() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		StringBuilder sb = new StringBuilder();
		BufferedReader br = request.getReader();
		String str = null;
		while ((str = br.readLine()) != null) {
			sb.append(str);
		}
		JSONObject jObj;
		UserInput userInput = null;
		try {
			jObj = new JSONObject(sb.toString());
			userInput = new UserInput(jObj.getString("a1"),
					jObj.getString("a2"), jObj.getString("b1"),
					jObj.getString("b2"), jObj.getString("c1"),
					jObj.getString("c2"), jObj.getString("c3"),
					jObj.getString("c4"), jObj.getString("c5"),
					jObj.getString("c6"), jObj.getString("d1"),
					jObj.getString("d2"), jObj.getString("e1"),
					jObj.getString("e2"));
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		List<Evaluation> evalRecList = null;
		List<Evaluation> evalRecList1 = new ArrayList<Evaluation>();
		List<String> recomdList = null;
		SecurityService secureService = new SecurityService();
		try {
			evalRecList = secureService.getAllEvaluationList(userInput);
			for (int i = 0; i < evalRecList.size() - 1; i++) {
				evalRecList1.add(evalRecList.get(i));
			}
			recomdList = secureService.getRecommendationList();
		} catch (JessException e) {
			e.printStackTrace();
		}

		EvalRecomdReponse reponse = new EvalRecomdReponse(evalRecList1,
				recomdList);

		String json = new Gson().toJson(reponse);
		response.setContentType("application/json");
		response.getWriter().write(json);

	}
}
