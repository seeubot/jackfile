// src/index.js
const VPNDetectionModule = require('./modules/vpnDetection');
const NetworkAnalysisModule = require('./modules/networkAnalysis');
const AnomalyDetectionModule = require('./modules/anomalyDetection');
const ContentFingerprintingModule = require('./modules/contentFingerprinting');
const { 
  generateUniqueId, 
  generateSecurityToken, 
  notifySecurityEvent 
} = require('./utils/helpers');

class ContentProtectionAPI {
  constructor(config) {
    this.config = {
      apiKey: config.apiKey,
      serviceName: config.serviceName,
      sensitivityLevel: config.sensitivityLevel || 'medium',
      blockingStrategy: config.blockingStrategy || 'immediate',
      notificationEndpoint: config.notificationEndpoint,
      loggingLevel: config.loggingLevel || 'info'
    };
    
    this.modules = {
      vpnDetection: new VPNDetectionModule(),
      networkAnalysis: new NetworkAnalysisModule(),
      anomalyDetection: new AnomalyDetectionModule(),
      contentFingerprinting: new ContentFingerprintingModule()
    };
    
    this.isInitialized = false;
    this.sessions = new Map();
  }
  
  async initialize(sessionInfo) {
    const sessionId = generateUniqueId();
    
    // Initialize all protection modules for this session
    await Promise.all([
      this.modules.vpnDetection.initialize(sessionInfo, this.config),
      this.modules.networkAnalysis.initialize(sessionInfo, this.config),
      this.modules.anomalyDetection.initialize(sessionInfo, this.config),
      this.modules.contentFingerprinting.initialize(sessionInfo, this.config)
    ]);
    
    // Store session info
    this.sessions.set(sessionId, {
      info: sessionInfo,
      startTime: new Date().toISOString(),
      status: 'active'
    });
    
    this.isInitialized = true;
    
    return {
      sessionId,
      securityToken: generateSecurityToken(sessionInfo, this.config),
      fingerprintData: this.modules.contentFingerprinting.getClientFingerprint()
    };
  }
  
  async checkSecurityStatus(sessionId) {
    if (!this.sessions.has(sessionId)) {
      return {
        error: 'Invalid session',
        secure: false,
        timestamp: new Date().toISOString()
      };
    }
    
    const threats = [];
    
    // Run all security checks in parallel
    const [vpnStatus, networkStatus, anomalyStatus, fingerprintStatus] = await Promise.all([
      this.modules.vpnDetection.checkStatus(sessionId),
      this.modules.networkAnalysis.checkStatus(sessionId),
      this.modules.anomalyDetection.checkStatus(sessionId),
      this.modules.contentFingerprinting.checkStatus(sessionId)
    ]);
    
    // Collect any detected threats
    if (vpnStatus.detected) threats.push({ type: 'vpn', details: vpnStatus });
    if (networkStatus.suspicious) threats.push({ type: 'network', details: networkStatus });
    if (anomalyStatus.anomalies.length > 0) threats.push({ type: 'anomaly', details: anomalyStatus });
    if (!fingerprintStatus.valid) threats.push({ type: 'fingerprint', details: fingerprintStatus });
    
    const securityStatus = {
      secure: threats.length === 0,
      timestamp: new Date().toISOString(),
      sessionId,
      threats
    };
    
    // Handle security breach if needed
    if (!securityStatus.secure) {
      this.handleSecurityBreach(sessionId, threats);
    }
    
    return securityStatus;
  }
  
  async handleSecurityBreach(sessionId, threats) {
    // Log the security breach
    this.logSecurityEvent(sessionId, 'breach', threats);
    
    // Notify backend via webhook if configured
    if (this.config.notificationEndpoint) {
      await notifySecurityEvent(this.config.notificationEndpoint, {
        sessionId,
        timestamp: new Date().toISOString(),
        threats,
        action: this.config.blockingStrategy
      });
    }
    
    // Take action based on configured blocking strategy
    switch (this.config.blockingStrategy) {
      case 'immediate':
        return this.terminateStream(sessionId, 'Security violation detected');
      case 'degraded':
        return this.degradeStreamQuality(sessionId);
      case 'warning':
        return this.issueWarning(sessionId, threats);
      default:
        return this.terminateStream(sessionId, 'Security violation detected');
    }
  }
  
  terminateStream(sessionId, reason) {
    // Update session status
    if (this.sessions.has(sessionId)) {
      const session = this.sessions.get(sessionId);
      session.status = 'terminated';
      session.terminatedReason = reason;
      session.terminatedAt = new Date().toISOString();
      this.sessions.set(sessionId, session);
    }
    
    // Signal to client that stream should be terminated
    return {
      action: 'terminate',
      reason,
      sessionId,
      timestamp: new Date().toISOString()
    };
  }
  
  degradeStreamQuality(sessionId) {
    // In a real implementation, this would signal to the client to reduce quality
    return {
      action: 'degrade',
      sessionId,
      timestamp: new Date().toISOString()
    };
  }
  
  issueWarning(sessionId, threats) {
    // In a real implementation, this would send a warning to the client
    return {
      action: 'warning',
      sessionId,
      threats,
      timestamp: new Date().toISOString()
    };
  }
  
  cleanup(sessionId) {
    if (!this.sessions.has(sessionId)) {
      return false;
    }
    
    // Update session status
    const session = this.sessions.get(sessionId);
    session.status = 'closed';
    session.closedAt = new Date().toISOString();
    this.sessions.set(sessionId, session);
    
    // Clean up module resources
    Object.values(this.modules).forEach(module => {
      if (typeof module.cleanup === 'function') {
        module.cleanup(sessionId);
      }
    });
    
    return true;
  }
  
  logSecurityEvent(sessionId, eventType, data) {
    const logData = {
      timestamp: new Date().toISOString(),
      sessionId,
      eventType,
      data
    };
    
    // Only log at appropriate levels
    if (this.config.loggingLevel === 'debug' || 
        (this.config.loggingLevel === 'info' && eventType !== 'routine') ||
        (this.config.loggingLevel === 'warning' && eventType === 'breach')) {
      console.log(JSON.stringify(logData));
    }
    
    // In a real implementation, this would send to a secure logging service
    return logData;
  }
}

module.exports = {
  ContentProtectionAPI
};
