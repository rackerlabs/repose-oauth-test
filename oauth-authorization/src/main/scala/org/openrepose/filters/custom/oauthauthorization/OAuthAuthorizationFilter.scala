/*
 * _=_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=
 * Repose
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Copyright (C) 2010 - 2015 Rackspace US, Inc.
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=_
 */
package org.openrepose.filters.custom.oauthauthorization

import java.net.URL
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Named}
import javax.servlet._
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import javax.ws.rs.core.MediaType

import com.rackspace.httpdelegation.HttpDelegationManager
import com.typesafe.scalalogging.slf4j.LazyLogging
import org.apache.commons.lang3.StringUtils
import org.openrepose.commons.config.manager.UpdateListener
import org.openrepose.commons.utils.http.ServiceClientResponse
import org.openrepose.commons.utils.servlet.http.{MutableHttpServletRequest, MutableHttpServletResponse, ReadableHttpServletResponse}
import org.openrepose.core.filter.FilterConfigHelper
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.services.datastore.DatastoreService
import org.openrepose.core.services.serviceclient.akka.AkkaServiceClient
import org.openrepose.filters.custom.oauthauthorization.config.OAuthAuthorizationConfig

import scala.collection.JavaConversions._
import scala.io.Source

@Named
class OAuthAuthorizationFilter @Inject()(configurationService: ConfigurationService,
                                         akkaServiceClient: AkkaServiceClient,
                                         datastoreService: DatastoreService)

  extends Filter
  with UpdateListener[OAuthAuthorizationConfig]
//  with HttpDelegationManager
  with LazyLogging {

  private final val DEFAULT_CONFIG = "oauth-authorization.cfg.xml"
  private final val KEY_PREFIX_STATE = "OAuth_STATE:"
  private final val KEY_PREFIX_TOKEN = "OAuth_TOKEN:"
  private final val KEY_PREFIX_DESTINATION = "OAuth_DESTINATION:"
  private val datastore = datastoreService.getDefaultDatastore
  private var initialized = false
  private var configurationFile: String = DEFAULT_CONFIG
  private var configuration: OAuthAuthorizationConfig = _
  private var delegationWithQuality: Option[Double] = _

  override def init(filterConfig: FilterConfig): Unit = {
    configurationFile = new FilterConfigHelper(filterConfig).getFilterConfig(DEFAULT_CONFIG)
    logger.info("Initializing filter using config " + configurationFile)
    // Must match the .xsd file created in step 18.
    val xsdURL: URL = getClass.getResource("/META-INF/schema/config/oauth-authorization.xsd")
    configurationService.subscribeTo(
      filterConfig.getFilterName,
      configurationFile,
      xsdURL,
      this,
      classOf[OAuthAuthorizationConfig]
    )
  }

  override def destroy(): Unit = {
    configurationService.unsubscribeFrom(configurationFile, this)
  }

  override def doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, filterChain: FilterChain): Unit = {
    if (!initialized) {
      logger.error("Filter not yet initialized...")
      servletResponse.asInstanceOf[HttpServletResponse].sendError(500)
    } else {
      val mutableHttpRequest = MutableHttpServletRequest.wrap(servletRequest.asInstanceOf[HttpServletRequest])
      val mutableHttpResponse = MutableHttpServletResponse.wrap(mutableHttpRequest, servletResponse.asInstanceOf[HttpServletResponse])

      // This is where this filter's custom logic is invoked.
      // For the purposes of this example, the configured messages are logged
      // before and after the Filter Chain is processed.
      if (handleRequest(mutableHttpRequest, mutableHttpResponse)) {
        //logger.trace("Passing Request on down the Filter Chain...")
        filterChain.doFilter(mutableHttpRequest, mutableHttpResponse)
        handleResponse(mutableHttpRequest, mutableHttpResponse)
      }
    }
    logger.trace("Returning response...")
  }

  // This class is generated from.xsd file.
  override def configurationUpdated(configurationObject: OAuthAuthorizationConfig): Unit = {
    logger.trace("Configuration Updated...")
    configuration = configurationObject
    initialized = true
  }

  override def isInitialized: Boolean = initialized

  case class TokenCreationInfo(responseCode: Int, userId: Option[String], userName: String, retry: String)

  def handleRequest(httpServletRequest: MutableHttpServletRequest, httpServletResponse: MutableHttpServletResponse): Boolean = {
    logger.trace("Processing request...")
    //////////
    // TODO: REMOVE THIS!!!
    httpServletRequest.addHeader(configuration.getEnclaveHeaderName, "this-is-a-test")
    // TODO: TESTING ONLY!!!
    //////////
    Option(httpServletRequest.getHeader(configuration.getEnclaveHeaderName)) match {
      case Some(user) =>
        logger.trace(s"Found ${configuration.getEnclaveHeaderName} with value $user")
        Option(datastore.get(KEY_PREFIX_TOKEN + user)) match {
          case Some(token) =>
            logger.trace(s"Found token $token")
            Option(datastore.get(KEY_PREFIX_DESTINATION + user)) match {
              case Some(destination) =>
                datastore.remove(KEY_PREFIX_DESTINATION + user)
                httpServletRequest.setRequestUri(destination.toString)
                logger.trace("Updated Request URI to pre-redirect value:" + httpServletRequest.getRequestURI)
              case None =>
                logger.trace("No saved Destination.")
            }
            httpServletRequest.getRequestURI match {
              case uri if uri.equals(configuration.getOauthRedirectUri) =>
                logger.trace("Authorization Redirect Return")
                Option(datastore.get(KEY_PREFIX_STATE + user)) match {
                  case Some(state) =>
                    logger.trace(s"Found saved state $state")
                    datastore.remove(KEY_PREFIX_STATE + user)
                    val stateString = state.toString
                    Option(httpServletRequest.getParameter("state")) match {
                      case Some(stateParam) if stateParam.equals(stateString) =>
                        logger.trace(s"Provided state $stateParam matches saved state.")
                        sendTokenRequest(httpServletRequest, user)
                      case None =>
                        logger.error("Provided State does NOT match saved State!")
                    }
                  case None =>
                    logger.error("No saved State found to compare to!")
                }
              case uri if uri.contains(configuration.getOauthMaskedUri) =>
                logger.trace("Masked Resource Request.")
                httpServletRequest.setRequestUri(uri.replace(configuration.getOauthMaskedUri, configuration.getOauthProxiedUri))
              case _ =>
                logger.trace("Requested URI: " + httpServletRequest.getRequestURI)
                logger.trace("Requested URL: " + httpServletRequest.getRequestURL)
            }
            makeProxiedRequest(httpServletRequest, token.toString) match {
              case Some(proxiedResponse) =>
                val resp = Source.fromInputStream(proxiedResponse.getData).getLines().mkString("\n")
                logger.trace("Received from OAuth'd Request:\n" + resp)
                true
              case None =>
                logger.error("Provided code is blank!")
                false
            }
          case None =>
            sendRedirect(httpServletRequest, httpServletResponse, user)
            false
        }
      case None =>
        logger.error(s"No ${configuration.getEnclaveHeaderName} header defined!")
        false
    }
  }

  def handleResponse(httpServletRequest: HttpServletRequest, httpServletResponse: ReadableHttpServletResponse): Unit = {
    logger.trace("Processing response...")

    val responseStatus = httpServletResponse.getStatus
    logger.debug("Incoming status code: " + responseStatus)
  }

  private def sendRedirect(httpServletRequest: MutableHttpServletRequest, httpServletResponse: MutableHttpServletResponse, user: String): Unit = {
    val uuid = UUID.randomUUID()
    datastore.put(KEY_PREFIX_DESTINATION + user, httpServletRequest.getRequestURI, 3600, TimeUnit.SECONDS)
    datastore.put(KEY_PREFIX_STATE + user, uuid, 3600, TimeUnit.SECONDS)
    httpServletResponse.sendRedirect(configuration.getOauthAuthorizeUri
      + "?client_id=" + configuration.getClientId
      + "&scope=" + configuration.getRequestedScope
      + "&redirect_uri=" + configuration.getOauthRedirectUri
      + "&state=" + uuid)
  }

  private def sendTokenRequest(httpServletRequest: MutableHttpServletRequest, user: String): Unit = {
    Option(httpServletRequest.getParameter("code")) match {
      case Some(code) if StringUtils.isNotBlank(code) =>
        val authTokenResponse = Option(akkaServiceClient.post("",
          configuration.getOauthAccessTokenUri
            + "?client_id=" + configuration.getClientId
            + "&client_secret=" + configuration.getClientSecret
            + "&code=" + code
            + "&redirect_uri=" + configuration.getOauthRedirectUri,
          Map[String, String]().empty,
          "",
          MediaType.APPLICATION_XML_TYPE))
        authTokenResponse match {
          case Some(token) if StringUtils.isNotBlank(token.getData.toString) =>
            datastore.put(KEY_PREFIX_TOKEN + user, token.toString)
          case None =>
            logger.error("Provided code is blank!")
        }
      case None =>
        logger.error("Provided code is blank!")
    }
  }

  private def makeProxiedRequest(httpServletRequest: MutableHttpServletRequest, accessToken: String): Option[ServiceClientResponse] = {
    httpServletRequest.getMethod match {
      case method if method.equalsIgnoreCase("GET") =>
        Option(akkaServiceClient.get(
          "",
          httpServletRequest.getRequestURI.replace(configuration.getOauthMaskedUri, configuration.getOauthProxiedUri) + "?access_token=" + accessToken,
          Map[String, String]().empty
        ))
      case method if method.equalsIgnoreCase("POST") =>
        Option(akkaServiceClient.post(
          "",
          httpServletRequest.getRequestURI.replace(configuration.getOauthMaskedUri, configuration.getOauthProxiedUri) + "?access_token=" + accessToken,
          Map[String, String]().empty,
          "",
          MediaType.APPLICATION_XML_TYPE
        ))
      case _ =>
        None
    }
  }
}
