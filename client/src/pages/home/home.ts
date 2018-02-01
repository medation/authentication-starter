import {Component} from '@angular/core';
import {JwtHelperService} from "@auth0/angular-jwt";
import {AuthenticationService} from "../../services/authentication";
import {HttpClient} from "@angular/common/http";

@Component({
  selector: 'page-home',
  templateUrl: 'home.html'
})
export class HomePage {
  user: string;
  message: string;

  constructor(private authenticationService: AuthenticationService,
              jwtHelper: JwtHelperService,
              private httpClient: HttpClient) {

    this.authenticationService.authUser.subscribe(jwt => {
      if (jwt) {
        const decoded = jwtHelper.decodeToken(jwt);
        this.user = decoded.sub
      }
      else {
        this.user = null;
      }
    });

  }


  logout() {
    this.authenticationService.logout();
  }

}
