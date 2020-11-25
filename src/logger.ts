import throttle from 'lodash/throttle'
import get from 'lodash/get'

interface LogEventDataMeta {
  [key: string]: any
}

interface LogEventData {
  eventType: 'exception' | 'log' | 'error' | 'warn' | 'securitypolicyviolation',
  name: string,
  timestamp: Date,
  message: string
  url: string,
  lineno?: number | undefined
  colno?: number | undefined
  source?: string | undefined
  event?: Event | undefined,
  stack?: string | undefined,
  eventMeta?: undefined | LogEventDataMeta
}

const defaultThrottleTime = 1000 * 10 // 10 seconds
const errorRetryTime = 1000 * 60 // 60 seconds
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
const reportWait = 1000 * 3 // 3 seconds

interface Options {
  url: string,
  throttleTime?: number,
  debug?: boolean,
  sendErrors?: boolean,
  sendInformation?: boolean,
  sendWarnings?: boolean,
  sendExceptions?: boolean,
  sendCSPViolations?: boolean,
  getSessionMeta?: () => object
}

const isProduction = get(window, 'process.env.NODE_ENV') === 'production'

class Logger {
  private log: typeof console.log
  private error: typeof console.error
  private warn: typeof console.warn
  private queue: LogEventData[] = []
  private onerror: typeof window.onerror
  readonly url: string
  readonly throttleTime: number
  readonly debug: boolean
  readonly throttledFlush: () => void
  readonly sendWarnings: boolean
  readonly sendErrors: boolean
  readonly sendInformation: boolean
  readonly sendExceptions: boolean
  readonly getSessionMeta: undefined | (() => object)

  constructor({ url, throttleTime, debug, sendErrors, sendExceptions, sendInformation, sendWarnings, sendCSPViolations, getSessionMeta }: Options) {
    this.throttleTime = throttleTime = throttleTime || defaultThrottleTime
    this.debug = debug = debug || false
    this.sendWarnings = sendWarnings = sendWarnings || false
    this.sendInformation = sendInformation = sendInformation || false
    this.sendErrors = sendErrors = sendErrors || true
    this.sendExceptions = sendExceptions = sendExceptions || true
    this.url = url
    this.throttleTime = throttleTime
    this.throttledFlush = throttle(this.flush, this.throttleTime)
    this.log = console.log
    this.error = console.error
    this.warn = console.warn
    this.onerror = window.onerror
    this.getSessionMeta = getSessionMeta
    window.addEventListener('beforeunload', this.flush)
    if (isProduction || debug) {
      if (sendInformation) console.log = this.onLog
      if (sendWarnings) console.warn = this.onWarn
      if (sendErrors) console.error = this.onError
      if (sendExceptions) window.onerror = this.onWindowError
      if (sendCSPViolations) document.addEventListener('securitypolicyviolation', this.handleCspViolation)
    }
  }

  private handleCspViolation = (e: SecurityPolicyViolationEvent) => {
    const data = {
      'blocked-uri': e.blockedURI,
      'document-uri': e.documentURI,
      'original-policy': e.originalPolicy,
      'referrer': e.referrer,
      // 'script-sample': e.sample,
      'timestamp': e.timeStamp,
      'source-file': e.sourceFile,
      'violated-directive': e.violatedDirective,
      'effective-directive': e.effectiveDirective,
      'line-number': e.lineNumber,
      'col-number': e.columnNumber,
      'status-code': e.statusCode,
    };

    let message = ''

    for (const key in data) {
      if (data.hasOwnProperty(key)) {
        message += key
        message += ' '
        message += data[key as keyof typeof data]
        message += '\n'
      }
    }

    const source = e.sourceFile
    const lineno = e.lineNumber
    const colno = e.columnNumber

    this.queue.push({
      eventType: 'securitypolicyviolation',
      name: 'securitypolicyviolation',
      message,
      source,
      lineno,
      colno,
      timestamp: new Date(e.timeStamp),
      url: document.location.href
    })
  }

  private report = () => setTimeout(this.throttledFlush, reportWait);

  private onWindowError: typeof window.onerror = (message, source, lineno, colno, error: Error | undefined) => {
    this.error(message, source, lineno, colno, error)
    if (error) this.captureError(error)
    else if (this.debug || isProduction) {
      if (this.sendExceptions) {
        this.queue.push({
          eventType: 'exception',
          name: 'window.onerror',
          message: typeof message === 'string' ? message : '',
          source,
          lineno,
          colno,
          timestamp: new Date(),
          url: document.location.href
        })
        this.report()
      }
      return this.onerror ?.call(window, message, source, lineno, colno, error)
    }
  }

  private onLog = (...args: any) => {
    if (this.sendInformation) {
      this.queue.push({
        eventType: 'log',
        name: 'console.log',
        message: args.join(', '),
        url: document.location.href,
        timestamp: new Date(),
        eventMeta: { args }
      });
      this.report()
    }
    return this.log.apply(console, args);
  }

  public logInformation = (name: string, message: string, eventMeta: object) => {
    this.queue.push({
      eventType: 'log',
      name,
      message,
      url: document.location.href,
      timestamp: new Date(),
      eventMeta
    });
    this.report()
  }

  private onWarn = (...args: any) => {
    if (this.sendWarnings) {
      this.queue.push({
        eventType: 'warn',
        name: 'console.warn',
        message: args.map((x: any) => typeof x !== 'string' ? JSON.stringify(x) : x).join(', '),
        url: document.location.href,
        timestamp: new Date(),
        eventMeta: { args }
      });
      this.report()
    }
    return this.warn.apply(console, args);
  }

  private onError = (...args: any) => {
    if (this.sendErrors) {
      this.queue.push({
        eventType: 'error',
        name: 'console.error',
        message: args.join(', '),
        url: document.location.href,
        timestamp: new Date(),
        eventMeta: { args }
      });
      this.report()
    }
    return this.error.apply(console, args);
  }

  flush = async () => {
    if (this.queue.length === 0) return
    const items = this.queue.splice(0, this.queue.length)
    const jsonDocument = {
      included: [{
        type: 'log-items-metadata',
        attributes: {
          appName: navigator.appName,
          appCodeName: navigator.appCodeName,
          platform: navigator.platform,
          ...(this.getSessionMeta ? await this.getSessionMeta() || undefined : undefined)
        }
      }],
      data: items.map(item => {
        let message = item.message
        if (typeof item.message === 'object') {
          try {
            message = JSON.stringify(item.message)
          } catch (err) {/* silence */}
        }
        return {
          type: `${item.eventType}-log-items`,
          attributes: {
            eventType: item.eventType,
            name: item.name,
            timestamp: item.timestamp,
            message,
            url: item.url,
            lineno: item.lineno,
            colno: item.colno,
            source: item.source,
            event: item.event,
            stack: item.stack,
            eventMeta: item.eventMeta
          }
        }
      })
    }

    try {
      const response = await window.fetch(this.url, {
        method: 'POST',
        body: JSON.stringify(jsonDocument),
        headers: {
          'Content-Type': 'application/json'
        }
      })
      if (!response.ok) throw response.statusText
    } catch (err) {
      this.queue.splice(0, 0, ...items)
      this.error.call(console, err)
      await sleep(errorRetryTime)
      if (this.queue.length === 0) return
      this.throttledFlush()
    }
  }

  captureError = (exception: Error, meta?: LogEventDataMeta | undefined) => {
    this.queue.push({
      eventType: 'exception',
      name: exception.name, // e.g. ReferenceError
      message: exception.message, // e.g. x is undefined
      url: document.location.href,
      stack: exception.stack, // stacktrace string; remember, different per-browser!
      timestamp: new Date(),
      eventMeta: meta
    })

    this.report()
  }
}

export default Logger
