import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute, ParamMap } from '@angular/router';
import { AuthenticationService } from '../authentication.service';
import { UserService } from '../user.service';


@Component({
  selector: 'app-callback',
  templateUrl: './callback.component.html',
  styleUrls: ['./callback.component.css']
})
export class CallbackComponent implements OnInit {

  constructor(private route: ActivatedRoute,
              private router: Router,
              private authService: AuthenticationService,
              private userService: UserService) { }

  async ngOnInit() {
    let path = window.location.pathname.split('/');
    var provider = path[path.length - 1];
    let resp = await this.authService.callback(
      provider, this.route.snapshot.queryParamMap['params']);
    this.authService.setJwtToken(resp.token);
    this.router.navigate['/profile']
  }

}
