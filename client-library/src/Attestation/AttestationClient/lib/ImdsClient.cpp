//-------------------------------------------------------------------------------------------------
// <copyright file="ImdsClient.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <curl/curl.h>
#include <json/json.h>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "Logging.h"
#include "ImdsClient.h"
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <regex>
#include <hw_evidence_manager.h>
#include "AttestationLibTelemetry.h"

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_RESOURCE_NOT_FOUND 404
#define HTTP_STATUS_TOO_MANY_REQUESTS 429
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define MAX_RETRIES 3
#define IMDS_ENVIRONMENT_MAX_RETRIES 5

constexpr char imds_endpoint[] = "http://169.254.169.254/metadata";
constexpr char azure_local_imds_endpoint[] = "http://localhost:40342/metadata";
constexpr char api_version_param[] = "api-version=";
constexpr char vm_id_param[] = "vmId=";
constexpr char request_id_param[] = "requestId=";
constexpr char cert_guid_param[] = "guid=";

size_t ImdsClient::WriteResponseCallback(void* contents, size_t size, size_t nmemb, void* response)
{
	if (response == nullptr ||
		contents == nullptr) {
		CLIENT_LOG_ERROR("Invalid input parameters");
		return 0;
	}
	std::string* responsePtr = reinterpret_cast<std::string*>(response);

	char* contentsStr = (char*)contents;
	size_t contentsSize = size * nmemb;

	responsePtr->insert(responsePtr->end(), contentsStr, contentsStr + contentsSize);
	 
	return contentsSize;
}

std::string ImdsClient::GetThimAkRenewEndpoint(const std::string& vm_id, const std::string& request_id, const std::string& api_version) {
	constexpr char ak_renew_path[] = "/THIM/tvm/certificate/renew";
	
	std::string url = std::string(imds_endpoint) +
		std::string(ak_renew_path) +
		std::string("?") +
		std::string(api_version_param) +
		api_version +
		std::string("&") +
		std::string(vm_id_param) +
		vm_id +
		std::string("&") +
		std::string(request_id_param) +
		request_id;

	CLIENT_LOG_INFO("AK renew url: %s", url.c_str());
	if (attest::telemetry_reporting.get() != nullptr) {
        attest::telemetry_reporting->UpdateEvent("AKRenew Url", 
										url.c_str(), 
										attest::TelemetryReportingBase::EventLevel::IMDS_RENEW_AK_URL);
    }

	return url;
}

std::string ImdsClient::GetThimQueryAkEndpoint(const std::string& vm_id, const std::string& request_id, const std::string& cert_query_guid) {
	constexpr char ak_query_cert_path[] = "/THIM/tvm/certificate/query";
	constexpr char api_version[] = "2021-12-01";

	std::string url = std::string(imds_endpoint) +
		std::string(ak_query_cert_path) +
		std::string("?") +
		std::string(api_version_param) +
		std::string(api_version) +
		std::string("&") +
		std::string(vm_id_param) +
		vm_id +
		std::string("&") +
		std::string(request_id_param) +
		request_id +
		std::string("&") +
		std::string(cert_guid_param) +
		cert_query_guid;

	CLIENT_LOG_INFO("AK query url: %s", url.c_str());
	return url;
}

std::string ImdsClient::GetVmIdQueryEndpoint() {
	constexpr char vm_id_query_path[] = "/instance/compute/vmId";
	constexpr char api_version[] = "2019-03-11";
	constexpr char format_type[] = "format=text";

	std::string url = std::string(imds_endpoint) +
		std::string(vm_id_query_path) +
		std::string("?") +
		std::string(api_version_param) +
		std::string(api_version) +
		std::string("&") +
		std::string(format_type);

	CLIENT_LOG_INFO("IMDS VM ID query url: %s", url.c_str());
	return url;
}

std::string ImdsClient::GetInstanceMetadataQueryEndpoint() {
	constexpr char instance_metadata_query_path[] = "/instance/compute";
	switch (attestation_environment_) {
		case attest::AttestationEnvironment::Azure: {
			constexpr char api_version[] = "2021-02-01";
			constexpr char format_type[] = "format=json";
			return std::string(imds_endpoint) +
				std::string(instance_metadata_query_path) +
				std::string("?") +
				std::string(api_version_param) +
				std::string(api_version) +
				std::string("&") +
				std::string(format_type);
		}
		case attest::AttestationEnvironment::AzureLocal: {
			constexpr char api_version[] = "2020-06-01";
			return std::string(azure_local_imds_endpoint) +
				std::string(instance_metadata_query_path) +
				std::string("?") +
				std::string(api_version_param) +
				std::string(api_version);
		}
		default:
			CLIENT_LOG_INFO("No known IMDS endpoint for the selected attestation environment");
			return std::string();
	}
}

std::string ImdsClient::GetVmId() {
	std::string url = GetVmIdQueryEndpoint();
	std::string vm_id = InvokeHttpRequest(url,
		ImdsClient::HttpVerb::GET);

	return vm_id;
}

std::string ImdsClient::GetInstanceMetadata() {
	if (!instance_metadata_.empty()) {
		return instance_metadata_;
	}

	std::string url = GetInstanceMetadataQueryEndpoint();
	if (url.empty()) {
		return std::string();
	}

	instance_metadata_ = InvokeHttpRequest(
		url,
		ImdsClient::HttpVerb::GET,
		std::string(),
		0);
	return instance_metadata_;
}

attest::AttestationEnvironment ImdsClient::GetAttestationEnvironment() {
	std::call_once(determine_environment_once_, &ImdsClient::DetermineEnvironment, this);
	return attestation_environment_;
}

void ImdsClient::DetermineEnvironment() {
	for (uint8_t retries = 0; retries <= IMDS_ENVIRONMENT_MAX_RETRIES; retries++) {
		attestation_environment_ = attest::AttestationEnvironment::Azure;
		if (!GetInstanceMetadata().empty()) {
			CLIENT_LOG_INFO("Attestation environment is Azure; detected through Azure IMDS");
			return;
		}

		attestation_environment_ = attest::AttestationEnvironment::AzureLocal;
		if (!GetInstanceMetadata().empty()) {
			CLIENT_LOG_INFO("Attestation environment is Azure Local; detected through Azure Local IMDS");
			return;
		}

		uint32_t attest_uri_size = 0;
		hw_evidence_result evidence_result = get_attest_uri(nullptr, &attest_uri_size);
		if (evidence_result == HW_EVIDENCE_OK) {
			CLIENT_LOG_INFO("Attestation environment is Azure Local; detected through Evidence SDK attest URI");
			return;
		}

		if (evidence_result == HW_EVIDENCE_ERROR_IGVM_ATTEST_URI_NOT_CONFIGURED) {
			CLIENT_LOG_INFO("Attestation environment is Azure Local; Evidence SDK reports attest URI is not configured");
			return;
		}

		CLIENT_LOG_INFO("Evidence SDK Azure Local probe failed with error: 0x%x",
			static_cast<unsigned int>(evidence_result));

		if (retries < IMDS_ENVIRONMENT_MAX_RETRIES) {
			std::this_thread::sleep_for(
				std::chrono::seconds(
					static_cast<long long>(5 * pow(2.0, static_cast<double>(retries)))));
		}
	}

	attestation_environment_ = attest::AttestationEnvironment::NonAzure;
	CLIENT_LOG_INFO("Attestation environment is non-Azure; Azure IMDS, Azure Local IMDS, and Evidence SDK probes failed");
}

std::string ImdsClient::RenewAkCert(
		const std::string& cert,
		const std::string& vm_id,
		const std::string& request_id,
		const std::string& api_version) {
	std::string ak_cert_renew_response;
	if (cert.empty() ||
		vm_id.empty() ||
		request_id.empty()) {
		CLIENT_LOG_ERROR("Invalid input parameter");
		if (attest::telemetry_reporting.get() != nullptr) {
			attest::telemetry_reporting->UpdateEvent("AkRenew", 
											"Invalid input parameter", 
											attest::TelemetryReportingBase::EventLevel::IMDS_RENEW_AK);
		}

		return ak_cert_renew_response;
	}

	std::string url = GetThimAkRenewEndpoint(vm_id, request_id, api_version);
	std::string url_encoded_cert = UrlEncode(cert);
	CLIENT_LOG_INFO("IMDS Ak renew request body: %s", url_encoded_cert.c_str());
	if (attest::telemetry_reporting.get() != nullptr) {
		attest::telemetry_reporting->UpdateEvent("AkRenew", 
										url_encoded_cert, 
										attest::TelemetryReportingBase::EventLevel::IMDS_AKRENEW_REQUEST_BODY);
	}

	ak_cert_renew_response = InvokeHttpRequest(url,
		ImdsClient::HttpVerb::POST,
		url_encoded_cert);

	return ak_cert_renew_response;
}

std::string ImdsClient::QueryAkCert(
		const std::string& cert_query_guid,
		const std::string& vm_id,
		const std::string& request_id) {
	std::string renewed_cert;
	if (cert_query_guid.empty() ||
		vm_id.empty() ||
		request_id.empty()) {
		CLIENT_LOG_ERROR("Invalid input parameter");
		if (attest::telemetry_reporting.get() != nullptr) {
			attest::telemetry_reporting->UpdateEvent("AkRenew", 
											"Invalid input parameter", 
											attest::TelemetryReportingBase::EventLevel::IMDS_QUERY_AK);
		}
		return renewed_cert;
	}

	std::string url = GetThimQueryAkEndpoint(vm_id, request_id, cert_query_guid);
	renewed_cert = InvokeHttpRequest(url,
		ImdsClient::HttpVerb::GET);

	return renewed_cert;
}

std::string ImdsClient::InvokeHttpRequest(
	const std::string& url,  
	const ImdsClient::HttpVerb& http_verb,
	const std::string& request_body,
	uint8_t max_retries) {
	std::string http_response;
	if (url.empty()) {
		CLIENT_LOG_ERROR("The URL can not be empty");
		return http_response;
	}

	CURL* curl = curl_easy_init();
	if (curl == nullptr) {
		CLIENT_LOG_ERROR("Failed to initialize curl for http request.");
		return http_response;
	}

	// Set the the HTTPHEADER object to send Metadata in the response.
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Metadata:true");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Send a pointer to a std::string to hold the response from the end
	// point along with the handler function.
	std::string response;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

	// Set the url of the end point that we are trying to talk to.
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	if (http_verb == ImdsClient::HttpVerb::POST) {
		if (request_body.empty()) {
			CLIENT_LOG_ERROR("Request body missing for POST request");
			return http_response;
		}

		// Set Http request to be a POST request as expected by the THIM endpoint.
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

		// set the payload that will be sent to the endpoint.
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_body.size());
	}

	// Adding timeout for 300 sec
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);

	CURLcode res = CURLE_OK;
	uint8_t retries = 0;
	while ((res = curl_easy_perform(curl)) == CURLE_OK) {
		long response_code = HTTP_STATUS_OK;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

		if (HTTP_STATUS_OK == response_code) {
			http_response = response;
			if (http_response.size() == 0) {
				CLIENT_LOG_ERROR("HTTP response found empty");
				break;
			}

			CLIENT_LOG_INFO("HTTP response retrieved: %s", http_response.c_str());
			break;
		}
		else if (response_code == HTTP_STATUS_RESOURCE_NOT_FOUND ||
			response_code == HTTP_STATUS_TOO_MANY_REQUESTS ||
			response_code >= HTTP_STATUS_INTERNAL_SERVER_ERROR) {
			//If we receive any of these responses from IMDS, we can retry
			//after an exponential backoff time
			// Sleep for the backoff period and try again
			if (retries == max_retries) {
				CLIENT_LOG_ERROR("HTTP request failed. Maximum retries exceeded\n");

				break;
			}
			CLIENT_LOG_ERROR("HTTP request failed with response code:%ld description:%s",
				response_code,
				response.c_str());
			CLIENT_LOG_INFO("Retrying HTTP request:%d", retries);
			// Retry with backoff 30 -> 60 -> 120 seconds
			std::this_thread::sleep_for(
				std::chrono::seconds(
					static_cast<long long>(30 * pow(2.0, static_cast<double>(retries++)))
				));
			response = std::string();
			continue;
		}
		else {
			CLIENT_LOG_ERROR("HTTP request failed with response code:%ld description:%s",
				response_code,
				response.c_str());
			break;
		}
	}

	if (res != CURLE_OK) {
		CLIENT_LOG_ERROR("curl_easy_perform() failed:%s", curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	return http_response;
}

std::string ImdsClient::UrlEncode(const std::string& data)
{
	std::string encoded_str;
	CURL* curl = curl_easy_init();
	if (curl) {
		char* output = curl_easy_escape(curl, data.c_str(), data.length());
		if (output) {
			encoded_str = output;
			curl_free(output);
		}
		curl_easy_cleanup(curl);
	}

	return encoded_str;
}