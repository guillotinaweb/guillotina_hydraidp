import { Component, OnInit } from '@angular/core';
import { ConfigurationService } from '../configuration.service';
import { AuthenticationService } from '../authentication.service';
import { Router, ActivatedRoute, ParamMap } from '@angular/router';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {

  providers: string[];
  baseUrl = '';

  constructor(public config: ConfigurationService,
              private authService: AuthenticationService,
              private router: Router) { }

  async ngOnInit() {
    this.providers = await this.authService.get_providers();
    
    this.baseUrl = this.config.get('BACKEND_URL') + '/@authenticate/';
  }

  getUrl(provider){
    var callback = window.location.origin + '/callback/' + provider;
    return this.baseUrl + provider + '?callback=' + callback;
  }

}
