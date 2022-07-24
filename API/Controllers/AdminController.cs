using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace API.Controllers
{
  public class AdminController : BaseApiController
  {
    public UserManager<AppUser> _userManager { get; set; }

    public AdminController(UserManager<AppUser> userManager)
    {
      _userManager = userManager;
    }

    [Authorize(Policy = "RequireAdminRole")]
    [HttpGet("users-with-roles")]
    public async Task<ActionResult> GetUserWithRoles()
    {
      var users = await _userManager.Users
        .Include(r => r.UserRoles)
        .ThenInclude(r => r.Role)
        .OrderBy(u => u.UserName)
        .Select(u => new
        {
          u.Id,
          username = u.UserName,
          Roles = u.UserRoles.Select(r => r.Role.Name).ToList()
        }).ToListAsync();

      return Ok(users);
    }

    [Authorize(Policy = "RequireAdminRole")]
    [HttpPost("edit-roles/{username}")]
    public async Task<ActionResult> editRoles(string userName, [FromQuery] string roles)
    {
      var selectedRoles = roles.Split(",").ToArray();

      var user = await _userManager.FindByNameAsync(userName);

      if (user == null) return NotFound("Could not find user");

      var userRoles = await _userManager.GetRolesAsync(user);

      var result = await _userManager.AddToRolesAsync(user, selectedRoles.Except(userRoles));

      if (!result.Succeeded) return BadRequest("Failed to add roles");

      result = await _userManager.RemoveFromRolesAsync(user, selectedRoles.Except(userRoles));

      if (!result.Succeeded) return BadRequest("Failed to remove from roles");
      
      return Ok(await _userManager.GetRolesAsync(user));
    }


    [Authorize(Policy = "ModerateFotoRole")]
    [HttpGet("photos-to-moderate")]
    public ActionResult GetPhotosForModerations()
    {
      return Ok("Admins or moderatos can see this");
    }
  }
}