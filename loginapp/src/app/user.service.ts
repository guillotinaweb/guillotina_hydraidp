import { Injectable } from '@angular/core';
import { AuthenticationService } from './authentication.service';
import { JwtHelperService } from '@auth0/angular-jwt';
import { User } from './user.model';


@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(
  	private autenticationService: AuthenticationService,
  	private jwtHelper: JwtHelperService) { }

  private setUserInfo (userInfo: User) {
    if (!userInfo) {
      localStorage.removeItem('user_info');
    } else {
      localStorage.setItem('user_info', JSON.stringify(userInfo));
    }
  }

  getUserInfo(): User {
  	const user_info = localStorage.getItem('user_info');
  	if (!user_info) {
	   	const token = this.autenticationService.getRawToken();
	   	if (token) {
	   		const new_info: User = <User>this.jwtHelper.decodeToken(token)
	   		this.setUserInfo(new_info);
	   		return new_info
	   	} else {
	   		return null
	   	}
  	} else {
  		return <User>JSON.parse(user_info)
  	}
  }

  get username() {
  	return this.getUserInfo().username
  }

  get last_name() {
  	return this.getUserInfo().last_name
  }

  get first_name() {
  	return this.getUserInfo().first_name
  }

}
