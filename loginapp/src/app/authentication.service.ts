import { Injectable } from '@angular/core';
import { ConfigurationService } from './configuration.service';
import { HttpClient } from '@angular/common/http';
import { Observable, ReplaySubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

  constructor(
  	public config: ConfigurationService,
    public http: HttpClient) { }

  async get_providers() {
    const url = this.config.get('BACKEND_URL') + '/@authentication-providers';
    return await this.http.get<any>(url, {withCredentials: true}).toPromise();
  }

  async login(username: string, password: string, challenge: string) {
    const auth_url = this.config.get('BACKEND_URL') + '/@hydra-login';
    const payload = {
      'username': username,
      'password': password,
      'challenge': challenge
    }

    // XXX need to handle different status codes here!!!
    let resp = await this.http.post<any>(
      auth_url, payload, {withCredentials: true}).toPromise();

    window.location.href = resp.url;
  }

  async get_consent(challenge) {
    const auth_url = this.config.get('BACKEND_URL') + '/@hydra-consent?consent_challenge=' + challenge;
    return await this.http.get<any>(
      auth_url, {withCredentials: true}).toPromise();

  }

  async deny_consent(challenge, csrf) {
    const auth_url = this.config.get('BACKEND_URL') + '/@hydra-consent?consent_challenge=' + challenge;
    let resp = await this.http.delete<any>(auth_url, {withCredentials: true}).toPromise();

    window.location.href = resp.url;
  }

  async approve_consent(challenge: string, csrf:string, remember: boolean, subject: string, requested_scope: string[]) {
    const auth_url = this.config.get('BACKEND_URL') + '/@hydra-consent';
    const payload = {
      'challenge': challenge,
      'requested_scope': requested_scope,
      'subject': subject,
      'remember': remember,
      'csrf': csrf
    }

    // XXX need to handle different status codes here!!!
    let resp = await this.http.post<any>(
      auth_url, payload, {withCredentials: true}).toPromise();

    window.location.href = resp.url;
    // resp = await this.http.get<any>(
    //   resp.url, {withCredentials: true}).toPromise();
  }

  async callback(provider, params) {
    var queryString = Object.keys(params).map((key) => {
      return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
    }).join('&');
    var callback = window.location.origin + '/callback/' + provider;
    const auth_url = this.config.get('BACKEND_URL') + '/@callback/' + provider +
      '?' + queryString + '&callback=' + callback;
    let resp = await this.http.get<any>(
      auth_url, {withCredentials: true}).toPromise();
    return resp;
  }

  refresh (): Observable<any>{
    // ToDo
    return
  }


  private setAccessToken (accessToken: string) {
    if (!accessToken) {
      localStorage.removeItem('access_token');
    } else {
      localStorage.setItem('access_token', accessToken);
    }
  }

  private setRefreshToken (refreshToken: string) {
    if (!refreshToken) {
      localStorage.removeItem('refresh_token');
    } else {
      localStorage.setItem('refresh_token', refreshToken);
    }
  }

  setJwtToken(jwt_token) {
    debugger;
    localStorage.setItem('raw_token', jwt_token);
  }

  getRawToken() {
    return localStorage.getItem('raw_token');
  }

  getAccessToken () {
    return localStorage.getItem('access_token');
  }

  getRefreshToken () {
    return localStorage.getItem('refresh_token');
  }

  isAuthenticated (): boolean {
    return !!this.getAccessToken();
  }

  async logout () {
    // ToDo : Close session on server
    this.setAccessToken(null);
    this.setRefreshToken(null);
  }
}
